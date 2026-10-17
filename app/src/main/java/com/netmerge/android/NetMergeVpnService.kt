package com.netmerge.android

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import core.Core
import core.Protector
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.NetworkInterface

/**
 * Captures all device traffic on a TUN interface and hands the raw fd to the
 * Go data plane (gVisor netstack + per-connection scheduler), which re-dials
 * every flow out through one of the physical networks (Wi-Fi / mobile data).
 */
class NetMergeVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.netmerge.android.START"
        const val ACTION_STOP = "com.netmerge.android.STOP"
        private const val NOTIF_ID = 1
        private const val CHANNEL_ID = "netmerge"
        private const val TAG = "NetMergeVpn"
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var tunFd: Int = -1
    private var engineStarted = false

    private var connectivityManager: ConnectivityManager? = null
    private var cellularCallback: ConnectivityManager.NetworkCallback? = null
    private var wifiCallback: ConnectivityManager.NetworkCallback? = null
    private var pushJob: Job? = null
    private var statsJob: Job? = null

    // Direct Network refs, always overwritten on onAvailable. Keyed by
    // transport, never by Android's churning netId, so binding never goes stale.
    @Volatile private var wifiNetwork: Network? = null
    @Volatile private var cellNetwork: Network? = null

    // Called by Go from the dialer's Control callback, pre-connect, so the
    // egress socket bypasses this VPN (no routing loop).
    private val protector = object : Protector {
        override fun protect(fd: Long) {
            this@NetMergeVpnService.protect(fd.toInt())
        }

        override fun bindAndProtect(fd: Long, networkType: Long): Boolean {
            val intFd = fd.toInt()
            // networkType: 1 = Wi-Fi, 2 = Cellular
            val targetNet = when (networkType) {
                1L -> wifiNetwork
                2L -> cellNetwork
                else -> null
            } ?: return false
            return try {
                // adoptFd takes ownership; detachFd gives it back without
                // closing, so Go's socket fd stays valid.
                val pfd = ParcelFileDescriptor.adoptFd(intFd)
                try {
                    // STEP 1: bindSocket FIRST (sets netId fwmark in netd).
                    targetNet.bindSocket(pfd.fileDescriptor)
                } finally {
                    pfd.detachFd()
                }
                // STEP 2: protect AFTER bindSocket so the protectedFromVpn
                // fwmark bit is never clobbered by netd's SELECT_NETWORK.
                this@NetMergeVpnService.protect(intFd)
            } catch (t: Throwable) {
                Log.w(TAG, "bindAndProtect failed", t)
                false
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            shutdownEngine()
            stopSelf()
            return START_NOT_STICKY
        }
        if (startForegroundWithNotification("Starting…")) {
            scope.launch { startEngine() }
        }
        return START_STICKY
    }

    private fun startEngine() {
        if (engineStarted) return // already running; ignore duplicate start
        try {
            Core.touch()
        } catch (t: Throwable) {
            fail("Native library failed to load: ${t.message}")
            return
        }

        val pfd = try {
            Builder()
                .setSession("NetMerge")
                .addAddress("10.8.0.2", 32)
                .addRoute("0.0.0.0", 1)
                .addRoute("128.0.0.0", 1)
                // IPv6 /1 pair too, otherwise v6 traffic silently bypasses the VPN
                .addRoute("::", 1)
                .addRoute("8000::", 1)
                .addDnsServer("10.8.0.1")
                .setMtu(1500)
                .setBlocking(false)
                .establish()
        } catch (t: Throwable) {
            Log.w(TAG, "establish failed", t)
            null
        }
        if (pfd == null) {
            fail("System refused the VPN tunnel")
            return
        }

        // The Go engine owns the fd from here on; never close the ParcelFileDescriptor.
        val fd = pfd.detachFd()
        tunFd = fd
        val err = try {
            Core.start(fd.toLong(), protector, "{}")
        } catch (t: Throwable) {
            "Core.start threw: ${t.message}"
        }
        if (err != "") {
            Log.w(TAG, "Core.start failed: $err")
            fail(err)
            return
        }

        engineStarted = true
        NetMergeState.error.value = null
        NetMergeState.running.value = true
        registerNetworkTracking()
        startStatsLoop()
        Log.i(TAG, "engine started on fd $fd")
    }

    private fun fail(message: String) {
        NetMergeState.error.value = message
        NetMergeState.running.value = false
        closeTunFd()
        stopSelf()
    }

    // ---- network tracking ----

    private fun registerNetworkTracking() {
        val cm = getSystemService(ConnectivityManager::class.java)
        connectivityManager = cm
        // Force both transports to stay up simultaneously for bonding.
        // requestNetwork() (not just register) asks the system to BRING UP
        // the network even if it wouldn't be the default (e.g. cellular
        // while on Wi-Fi). Without this, Android suspends mobile data.
        // NOTE: requires CHANGE_NETWORK_STATE permission.
        try {
            val wifiReq = NetworkRequest.Builder()
                .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()
            wifiCallback = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    wifiNetwork = network // ALWAYS overwrite with latest!
                    Log.i(TAG, "wifi available: $network")
                    schedulePush()
                }
                override fun onLost(network: Network) {
                    if (wifiNetwork == network) {
                        wifiNetwork = null
                        Log.i(TAG, "wifi lost")
                        schedulePush()
                    }
                }
            }
            cm.requestNetwork(wifiReq, wifiCallback!!)
            val cellReq = NetworkRequest.Builder()
                .addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()
            cellularCallback = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    cellNetwork = network // ALWAYS overwrite with latest!
                    Log.i(TAG, "cellular available: $network")
                    schedulePush()
                }
                override fun onLost(network: Network) {
                    if (cellNetwork == network) {
                        cellNetwork = null
                        Log.i(TAG, "cellular lost")
                        schedulePush()
                    }
                }
            }
            cm.requestNetwork(cellReq, cellularCallback!!)
            Log.i(TAG, "requested both cellular and wifi networks")
        } catch (t: Throwable) {
            Log.w(TAG, "requestNetwork failed", t)
        }
        pushNetworks() // initial snapshot
    }

    private fun unregisterNetworkTracking() {
        val cm = connectivityManager ?: return
        try { wifiCallback?.let { cm.unregisterNetworkCallback(it) } } catch (_: Exception) {}
        try { cellularCallback?.let { cm.unregisterNetworkCallback(it) } } catch (_: Exception) {}
        wifiCallback = null
        cellularCallback = null
    }

    private fun schedulePush() {
        pushJob?.cancel()
        pushJob = scope.launch {
            delay(500) // debounce rapid flapping
            pushNetworks()
        }
    }

    private fun pushNetworks() {
        val cm = connectivityManager ?: return
        try {
            val arr = JSONArray()
            // Canonical slot IDs: "wifi" and "cellular". Never use Android's
            // churning netId — Go keys slots by this ID, so duplicates vanish.
            wifiNetwork?.let { network ->
                val info = networkInfoJson(cm, network, "wifi", "Wi-Fi", "WIFI")
                if (info != null) arr.put(info)
            }
            cellNetwork?.let { network ->
                val info = networkInfoJson(cm, network, "cellular", "Mobile", "CELLULAR")
                if (info != null) arr.put(info)
            }
            Core.updateNetworks(arr.toString())
        } catch (t: Throwable) {
            Log.w(TAG, "pushNetworks failed", t)
        }
    }

    private fun networkInfoJson(
        cm: ConnectivityManager, network: Network,
        id: String, displayName: String, transport: String
    ): JSONObject? {
        return try {
            val lp = cm.getLinkProperties(network) ?: return null
            val ifName = lp.interfaceName ?: return null
            val ifIndex = try {
                NetworkInterface.getByName(ifName)?.index ?: 0
            } catch (_: Exception) { 0 }
            var ipv4 = ""
            var ipv6 = ""
            for (la in lp.linkAddresses) {
                val addr = la.address ?: continue
                if (addr.isLinkLocalAddress || addr.isLoopbackAddress) continue
                if (addr is Inet4Address && ipv4.isEmpty()) ipv4 = addr.hostAddress ?: ""
                if (addr is Inet6Address && ipv6.isEmpty()) ipv6 = addr.hostAddress ?: ""
            }
            val dns = JSONArray()
            for (d in lp.dnsServers) { d.hostAddress?.let { dns.put(it) } }
            JSONObject()
                .put("id", id)
                .put("name", ifName)
                .put("displayName", displayName)
                .put("transport", transport)
                .put("ifindex", ifIndex)
                .put("ipv4", ipv4)
                .put("ipv6", ipv6)
                .put("dns", dns)
        } catch (t: Throwable) {
            Log.w(TAG, "networkInfoJson failed for $id", t)
            null
        }
    }

    // ---- stats + notification ----

    private fun startStatsLoop() {
        statsJob?.cancel()
        statsJob = scope.launch {
            while (isActive) {
                try {
                    val json = Core.getStats()
                    NetMergeState.updateFromJson(json)
                    updateNotification()
                } catch (t: Throwable) {
                    Log.w(TAG, "getStats failed", t)
                }
                delay(1000)
            }
        }
    }

    private fun buildNotification(text: String): android.app.Notification {
        val pi = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("NetMerge")
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_stat)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }

    /**
     * Returns false when the service could not go foreground (fail() already
     * called); the caller must not start the engine in that case.
     */
    private fun startForegroundWithNotification(text: String): Boolean {
        val nm = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "NetMerge", NotificationManager.IMPORTANCE_LOW)
            )
        }
        return try {
            val type = if (Build.VERSION.SDK_INT >= 29)
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE else 0
            ServiceCompat.startForeground(this, NOTIF_ID, buildNotification(text), type)
            true
        } catch (se: SecurityException) {
            // POST_NOTIFICATIONS denied on Android 13+: we cannot run as a
            // foreground service without it.
            Log.w(TAG, "startForeground denied", se)
            fail("Please allow notifications for NetMerge, then try again.")
            false
        }
    }

    private fun updateNotification() {
        val s = NetMergeState.stats.value
        val up = s.networks.count { it.state == "up" }
        val text = if (s.running)
            "Bonding $up link(s) · ↓ ${formatBytes(s.totals.rxBytes)} ↑ ${formatBytes(s.totals.txBytes)}"
        else "Stopped"
        try {
            getSystemService(NotificationManager::class.java)
                .notify(NOTIF_ID, buildNotification(text))
        } catch (t: Throwable) {
            Log.w(TAG, "notification update failed", t)
        }
    }

    // ---- teardown ----

    private fun shutdownEngine() {
        networkCallback?.let { cb ->
            try {
                connectivityManager?.unregisterNetworkCallback(cb)
            } catch (_: Exception) {
            }
        }
        networkCallback = null
        connectivityManager = null
        pushJob?.cancel()
        pushJob = null
        statsJob?.cancel()
        statsJob = null
        if (engineStarted) {
            try {
                Core.stop()
            } catch (_: Throwable) {
            }
            engineStarted = false
        }
        closeTunFd()
        NetMergeState.running.value = false
    }

    private fun closeTunFd() {
        val fd = tunFd
        tunFd = -1
        if (fd >= 0) {
            try {
                ParcelFileDescriptor.adoptFd(fd).close()
            } catch (_: Exception) {
            }
        }
    }

    override fun onDestroy() {
        scope.cancel()
        unregisterNetworkTracking()
        shutdownEngine()
        super.onDestroy()
    }
}
