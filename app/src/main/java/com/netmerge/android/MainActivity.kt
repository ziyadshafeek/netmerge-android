package com.netmerge.android

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import com.netmerge.android.ui.theme.NetMergeTheme
import core.Core

class MainActivity : ComponentActivity() {

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) startVpnService()
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) {
        // Proceed regardless; if denied, the service reports a clear error
        // instead of crashing on startForeground.
        requestVpnPermission()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        try {
            Core.touch()
        } catch (t: Throwable) {
            NetMergeState.error.value = "Native library failed to load: ${t.message}"
        }
        ensureBatteryOptimizationExempt()
        setContent {
            NetMergeTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    MainScreen(
                        onToggle = {
                            if (NetMergeState.running.value) stopVpn()
                            else ensurePermissionAndStart()
                        }
                    )
                }
            }
        }
    }
    // ColorOS / OxygenOS / MIUI freeze background work unless the app is on
    // Android's Doze whitelist. Prompt once on launch.
    private fun ensureBatteryOptimizationExempt() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return
        try {
            val pm = getSystemService(PowerManager::class.java) ?: return
            if (!pm.isIgnoringBatteryOptimizations(packageName)) {
                val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                    data = Uri.parse("package:$packageName")
                }
                startActivity(intent)
            }
        } catch (_: Exception) { }
    }


    private fun ensurePermissionAndStart() {
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            requestVpnPermission()
        }
    }

    private fun requestVpnPermission() {
        val intent = VpnService.prepare(this)
        if (intent != null) vpnPermissionLauncher.launch(intent)
        else startVpnService()
    }

    private fun startVpnService() {
        NetMergeState.error.value = null
        val i = Intent(this, NetMergeVpnService::class.java)
            .setAction(NetMergeVpnService.ACTION_START)
        ContextCompat.startForegroundService(this, i)
    }

    private fun stopVpn() {
        val i = Intent(this, NetMergeVpnService::class.java)
            .setAction(NetMergeVpnService.ACTION_STOP)
        startService(i)
    }
}

@Composable
fun MainScreen(onToggle: () -> Unit) {
    val running by NetMergeState.running.collectAsState()
    val error by NetMergeState.error.collectAsState()
    val stats by NetMergeState.stats.collectAsState()

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        item {
            Text(
                "NetMerge",
                fontSize = 30.sp,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.primary
            )
            Text(
                "Use Wi-Fi + mobile data at once",
                fontSize = 14.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }

        item {
            StatusCard(running = running, error = error)
        }

        item {
            Button(
                onClick = onToggle,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(56.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (running) MaterialTheme.colorScheme.error
                    else MaterialTheme.colorScheme.primary,
                    contentColor = if (running) Color.White
                    else MaterialTheme.colorScheme.onPrimary
                )
            ) {
                Text(
                    if (running) "Stop bonding" else "Start bonding",
                    fontSize = 18.sp,
                    fontWeight = FontWeight.SemiBold
                )
            }
        }

        item {
            TotalsCard(stats = stats)
        }

        item {
            Text(
                "Links",
                fontSize = 18.sp,
                fontWeight = FontWeight.SemiBold
            )
        }

        if (stats.networks.isEmpty()) {
            item {
                Text(
                    if (running) "Waiting for network info…"
                    else "Start bonding to detect your Wi-Fi and mobile data links.",
                    fontSize = 14.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        } else {
            items(stats.networks, key = { it.id }) { net ->
                NetworkCard(net = net)
            }
        }

        item {
            HowItWorksCard()
            Spacer(Modifier.height(8.dp))
        }
    }
}

@Composable
fun StatusCard(running: Boolean, error: String?) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant
        )
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            val dotColor = if (running) Color(0xFF4ADE80) else Color(0xFF6B7280)
            androidx.compose.foundation.Canvas(
                modifier = Modifier.size(12.dp)
            ) { drawCircle(dotColor) }
            Spacer(Modifier.width(10.dp))
            Column {
                Text(
                    if (running) "Bonding active" else "Stopped",
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 16.sp
                )
                if (error != null) {
                    Text(
                        error,
                        fontSize = 13.sp,
                        color = MaterialTheme.colorScheme.error
                    )
                } else if (!running) {
                    Text(
                        "All traffic goes through your normal connection.",
                        fontSize = 13.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    }
}

@Composable
fun TotalsCard(stats: StatsSnapshot) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            horizontalArrangement = Arrangement.SpaceEvenly
        ) {
            TotalItem("↓ Down", formatBytes(stats.totals.rxBytes))
            TotalItem("↑ Up", formatBytes(stats.totals.txBytes))
            TotalItem("Flows", stats.totals.activeFlows.toString())
        }
    }
}

@Composable
fun TotalItem(label: String, value: String) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(label, fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, fontSize = 18.sp, fontWeight = FontWeight.Bold)
    }
}

@Composable
fun NetworkCard(net: NetworkStat) {
    val stateColor = when (net.state) {
        "up" -> Color(0xFF4ADE80)
        "unknown" -> Color(0xFFFBBF24)
        else -> Color(0xFFF87171)
    }
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        ),
        shape = RoundedCornerShape(14.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                androidx.compose.foundation.Canvas(modifier = Modifier.size(10.dp)) {
                    drawCircle(stateColor)
                }
                Spacer(Modifier.width(8.dp))
                Text(
                    net.displayName.ifEmpty { net.id },
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 16.sp,
                    modifier = Modifier.weight(1f)
                )
                Text(
                    transportLabel(net.transport),
                    fontSize = 12.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier
                        .clip(RoundedCornerShape(8.dp))
                        .padding(horizontal = 2.dp)
                )
            }
            Spacer(Modifier.height(8.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    "↓ ${formatBytes(net.rxBytes)}   ↑ ${formatBytes(net.txBytes)}",
                    fontSize = 13.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    "${net.activeFlows} flows · ×${String.format("%.1f", net.weight)}",
                    fontSize = 13.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Text(
                "Status: ${net.state}",
                fontSize = 12.sp,
                color = stateColor
            )
        }
    }
}

@Composable
fun HowItWorksCard() {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        ),
        shape = RoundedCornerShape(14.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text("How it works", fontWeight = FontWeight.SemiBold, fontSize = 16.sp)
            Spacer(Modifier.height(6.dp))
            Text(
                "NetMerge spreads each new connection across your links — " +
                    "some go over Wi-Fi, some over mobile data. " +
                    "Many connections at once (downloads, streaming, browsing) " +
                    "use the combined speed. One single connection still " +
                    "travels over one link, so it can't exceed that link's own speed.",
                fontSize = 13.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                lineHeight = 19.sp
            )
        }
    }
}
