import SwiftUI
import Charts

struct NetworkTrafficChart: View {
    let data: [NetworkTrafficPoint]
    let timeRange: TimeRange

    /// Convert raw MB/s values to KB/s for internal charting
    private var chartEntries: [ChartEntry] {
        data.map { point in
            ChartEntry(
                timestamp: point.timestamp,
                downloadKBs: point.downloadSpeed * 1024.0,
                uploadKBs: point.uploadSpeed * 1024.0
            )
        }
    }

    /// Peak value across both series (in KB/s)
    private var peakKBs: Double {
        let entries = chartEntries
        let maxDown = entries.map(\.downloadKBs).max() ?? 0
        let maxUp = entries.map(\.uploadKBs).max() ?? 0
        return max(maxDown, maxUp)
    }

    /// Show MB/s only when peak exceeds 1 MB/s (1024 KB/s)
    private var useMB: Bool {
        peakKBs >= 1024.0
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            // Legend row
            HStack(spacing: 16) {
                HStack(spacing: 4) {
                    Circle().fill(Color.blue).frame(width: 6, height: 6)
                    Text("Download").font(.caption2).foregroundColor(.secondary)
                }
                HStack(spacing: 4) {
                    Circle().fill(Color.green).frame(width: 6, height: 6)
                    Text("Upload").font(.caption2).foregroundColor(.secondary)
                }
                Spacer()
                if peakKBs > 0 {
                    Text("Peak: \(formatSpeed(peakKBs))")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }
            }

            if data.count < 2 {
                ZStack {
                    RoundedRectangle(cornerRadius: 8)
                        .fill(Color.gray.opacity(0.1))
                    VStack(spacing: 4) {
                        Image(systemName: "chart.xyaxis.line")
                            .font(.title3)
                            .foregroundColor(.secondary)
                        Text("Collecting data...")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
            } else {
                Chart {
                    ForEach(chartEntries) { entry in
                        // Download area + line (blue)
                        AreaMark(
                            x: .value("Time", entry.timestamp),
                            yStart: .value("Baseline", 0),
                            yEnd: .value("Download", entry.downloadKBs)
                        )
                        .foregroundStyle(
                            .linearGradient(
                                colors: [Color.blue.opacity(0.3), Color.blue.opacity(0.05)],
                                startPoint: .top,
                                endPoint: .bottom
                            )
                        )
                        .interpolationMethod(.catmullRom)

                        LineMark(
                            x: .value("Time", entry.timestamp),
                            y: .value("Download", entry.downloadKBs)
                        )
                        .foregroundStyle(Color.blue)
                        .lineStyle(StrokeStyle(lineWidth: 1.5))
                        .interpolationMethod(.catmullRom)

                        // Upload area + line (green)
                        AreaMark(
                            x: .value("Time", entry.timestamp),
                            yStart: .value("Baseline", 0),
                            yEnd: .value("Upload", entry.uploadKBs)
                        )
                        .foregroundStyle(
                            .linearGradient(
                                colors: [Color.green.opacity(0.3), Color.green.opacity(0.05)],
                                startPoint: .top,
                                endPoint: .bottom
                            )
                        )
                        .interpolationMethod(.catmullRom)

                        LineMark(
                            x: .value("Time", entry.timestamp),
                            y: .value("Upload", entry.uploadKBs)
                        )
                        .foregroundStyle(Color.green)
                        .lineStyle(StrokeStyle(lineWidth: 1.5))
                        .interpolationMethod(.catmullRom)
                    }
                }
                .chartXAxis {
                    AxisMarks(values: .automatic(desiredCount: 5)) { value in
                        AxisGridLine(stroke: StrokeStyle(lineWidth: 0.3))
                            .foregroundStyle(Color.gray.opacity(0.3))
                        if let date = value.as(Date.self) {
                            AxisValueLabel {
                                Text(formatTimeLabel(date))
                                    .font(.system(size: 9))
                                    .foregroundColor(.secondary)
                            }
                        }
                    }
                }
                .chartYAxis {
                    AxisMarks(position: .leading, values: .automatic(desiredCount: 4)) { value in
                        AxisGridLine(stroke: StrokeStyle(lineWidth: 0.3))
                            .foregroundStyle(Color.gray.opacity(0.3))
                        if let speed = value.as(Double.self) {
                            AxisValueLabel {
                                Text(formatSpeed(speed))
                                    .font(.system(size: 9))
                                    .foregroundColor(.secondary)
                            }
                        }
                    }
                }
                .chartYScale(domain: 0...(max(peakKBs * 1.2, 1.0)))
                .chartLegend(.hidden)
            }
        }
    }

    // MARK: - Formatting

    private func formatSpeed(_ kbPerSec: Double) -> String {
        if useMB {
            let mb = kbPerSec / 1024.0
            if mb >= 10.0 {
                return String(format: "%.0f MB/s", mb)
            }
            return String(format: "%.1f MB/s", mb)
        } else if kbPerSec >= 1.0 {
            return String(format: "%.0f KB/s", kbPerSec)
        } else if kbPerSec > 0 {
            return String(format: "%.1f KB/s", kbPerSec)
        } else {
            return "0 KB/s"
        }
    }

    private func formatTimeLabel(_ date: Date) -> String {
        let elapsed = Date().timeIntervalSince(date)
        if elapsed < 60 {
            return "\(Int(elapsed))s ago"
        } else if elapsed < 3600 {
            return "\(Int(elapsed / 60))m ago"
        } else {
            let formatter = DateFormatter()
            formatter.dateFormat = "h:mm a"
            return formatter.string(from: date)
        }
    }
}

// MARK: - Chart Data Entry

private struct ChartEntry: Identifiable {
    let id = UUID()
    let timestamp: Date
    let downloadKBs: Double
    let uploadKBs: Double
}
