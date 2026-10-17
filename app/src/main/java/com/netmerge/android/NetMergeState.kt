package com.netmerge.android

import kotlinx.coroutines.flow.MutableStateFlow
import org.json.JSONObject

/** One physical network as reported by the Go data plane. */
data class NetworkStat(
    val id: String,
    val displayName: String,
    val transport: String,
    val state: String, // up | unknown | down
    val txBytes: Long,
    val rxBytes: Long,
    val activeFlows: Int,
    val weight: Double,
)

data class Totals(val txBytes: Long, val rxBytes: Long, val activeFlows: Int)

data class StatsSnapshot(
    val running: Boolean,
    val networks: List<NetworkStat> = emptyList(),
    val totals: Totals = Totals(0, 0, 0),
)

/** Shared UI state, written by NetMergeVpnService, read by MainActivity. */
object NetMergeState {
    val running = MutableStateFlow(false)
    val error = MutableStateFlow<String?>(null)
    val stats = MutableStateFlow(StatsSnapshot(false))

    fun updateFromJson(json: String) {
        stats.value = try {
            parseStats(json)
        } catch (_: Exception) {
            stats.value
        }
    }

    private fun parseStats(json: String): StatsSnapshot {
        val root = JSONObject(json)
        val nets = mutableListOf<NetworkStat>()
        val arr = root.optJSONArray("networks")
        if (arr != null) {
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                nets += NetworkStat(
                    id = o.optString("id"),
                    displayName = o.optString("displayName").ifEmpty { o.optString("name") },
                    transport = o.optString("transport"),
                    state = o.optString("state"),
                    txBytes = o.optLong("txBytes"),
                    rxBytes = o.optLong("rxBytes"),
                    activeFlows = o.optInt("activeFlows"),
                    weight = o.optDouble("weight", 1.0),
                )
            }
        }
        val t = root.optJSONObject("totals")
        return StatsSnapshot(
            running = root.optBoolean("running"),
            networks = nets,
            totals = Totals(
                txBytes = t?.optLong("txBytes") ?: 0,
                rxBytes = t?.optLong("rxBytes") ?: 0,
                activeFlows = t?.optInt("activeFlows") ?: 0,
            ),
        )
    }
}

fun formatBytes(bytes: Long): String {
    if (bytes < 1024) return "$bytes B"
    val kb = bytes / 1024.0
    if (kb < 1024) return String.format("%.1f KB", kb)
    val mb = kb / 1024.0
    if (mb < 1024) return String.format("%.1f MB", mb)
    return String.format("%.2f GB", mb / 1024.0)
}

fun transportLabel(transport: String): String = when (transport) {
    "WIFI" -> "Wi-Fi"
    "CELLULAR" -> "Mobile"
    "ETHERNET" -> "Ethernet"
    else -> transport.ifEmpty { "Link" }
}
