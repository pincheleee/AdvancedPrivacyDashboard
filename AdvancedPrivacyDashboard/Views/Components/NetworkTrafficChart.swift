import SwiftUI
import Charts

struct NetworkTrafficChart: View {
    let data: [NetworkTrafficPoint]
    @Binding var timeRange: TimeRange

    @State private var selectedEntry: ChartEntry?
    @State private var ruleMark: Date?

    var body: some View {
        let entries = data.map { point in
            ChartEntry(
                timestamp: point.timestamp,
                downloadKBs: point.downloadSpeed * 1024.0,
                uploadKBs: point.uploadSpeed * 1024.0
            )
        }

        let peakKBs = {
            let maxDown = entries.map(\.downloadKBs).max() ?? 0
            let maxUp = entries.map(\.uploadKBs).max() ?? 0
            return max(maxDown, maxUp)
        }()

        let useMB = peakKBs >= 1024.0

        VStack(alignment: .leading, spacing: 12) {
            // Header row: title + time range picker
            HStack {
                Text("Network Traffic")
                    .font(.headline)
                Spacer()
                Picker("", selection: $timeRange) {
                    ForEach(TimeRange.allCases) { range in
                        Text(range.shortLabel).tag(range)
                    }
                }
                .pickerStyle(.segmented)
                .frame(width: 240)
            }

            // Stats row: legend + live stats
            HStack(spacing: 20) {
                HStack(spacing: 6) {
                    RoundedRectangle(cornerRadius: 2)
                        .fill(Color.blue)
                        .frame(width: 12, height: 4)
                    Text("Download")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                    Text(formatSpeed(entries.last?.downloadKBs ?? 0, useMB: useMB))
                        .font(.system(.caption2, design: .monospaced))
                        .fontWeight(.medium)
                        .foregroundColor(.blue)
                }
                HStack(spacing: 6) {
                    RoundedRectangle(cornerRadius: 2)
                        .fill(Color.green)
                        .frame(width: 12, height: 4)
                    Text("Upload")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                    Text(formatSpeed(entries.last?.uploadKBs ?? 0, useMB: useMB))
                        .font(.system(.caption2, design: .monospaced))
                        .fontWeight(.medium)
                        .foregroundColor(.green)
                }
                Spacer()
                if peakKBs > 0 {
                    HStack(spacing: 4) {
                        Image(systemName: "arrow.up.to.line")
                            .font(.system(size: 8))
                            .foregroundColor(.secondary)
                        Text("Peak: \(formatSpeed(peakKBs, useMB: useMB))")
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }
                }
                Text("\(entries.count) pts")
                    .font(.caption2)
                    .foregroundColor(.secondary.opacity(0.6))
            }

            // Chart
            if entries.count < 2 {
                ZStack {
                    RoundedRectangle(cornerRadius: 8)
                        .fill(Color.gray.opacity(0.08))
                    VStack(spacing: 6) {
                        ProgressView()
                            .controlSize(.small)
                        Text("Collecting data\u{2026}")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Text("Traffic will appear as network activity is detected.")
                            .font(.caption2)
                            .foregroundColor(.secondary.opacity(0.7))
                    }
                }
                .frame(height: 200)
            } else {
                Chart {
                    ForEach(entries) { entry in
                        // Download area + line
                        AreaMark(
                            x: .value("Time", entry.timestamp),
                            yStart: .value("Baseline", 0),
                            yEnd: .value("Download", entry.downloadKBs)
                        )
                        .foregroundStyle(
                            .linearGradient(
                                colors: [
                                    Color.blue.opacity(0.35),
                                    Color.blue.opacity(0.12),
                                    Color.blue.opacity(0.02)
                                ],
                                startPoint: .top,
                                endPoint: .bottom
                            )
                        )
                        .interpolationMethod(.catmullRom)

                        LineMark(
                            x: .value("Time", entry.timestamp),
                            y: .value("Download", entry.downloadKBs),
                            series: .value("Series", "Download")
                        )
                        .foregroundStyle(Color.blue)
                        .lineStyle(StrokeStyle(lineWidth: 2.0, lineCap: .round, lineJoin: .round))
                        .interpolationMethod(.catmullRom)

                        // Upload area + line
                        AreaMark(
                            x: .value("Time", entry.timestamp),
                            yStart: .value("Baseline", 0),
                            yEnd: .value("Upload", entry.uploadKBs)
                        )
                        .foregroundStyle(
                            .linearGradient(
                                colors: [
                                    Color.green.opacity(0.25),
                                    Color.green.opacity(0.08),
                                    Color.green.opacity(0.01)
                                ],
                                startPoint: .top,
                                endPoint: .bottom
                            )
                        )
                        .interpolationMethod(.catmullRom)

                        LineMark(
                            x: .value("Time", entry.timestamp),
                            y: .value("Upload", entry.uploadKBs),
                            series: .value("Series", "Upload")
                        )
                        .foregroundStyle(Color.green)
                        .lineStyle(StrokeStyle(lineWidth: 2.0, lineCap: .round, lineJoin: .round))
                        .interpolationMethod(.catmullRom)
                    }

                    // Selection rule line
                    if let mark = ruleMark {
                        RuleMark(x: .value("Selected", mark))
                            .foregroundStyle(Color.primary.opacity(0.3))
                            .lineStyle(StrokeStyle(lineWidth: 1, dash: [4, 3]))
                    }
                }
                .chartXAxis {
                    AxisMarks(values: .automatic(desiredCount: 6)) { value in
                        AxisGridLine(stroke: StrokeStyle(lineWidth: 0.5, dash: [3, 3]))
                            .foregroundStyle(Color.gray.opacity(0.2))
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
                        AxisGridLine(stroke: StrokeStyle(lineWidth: 0.5, dash: [3, 3]))
                            .foregroundStyle(Color.gray.opacity(0.2))
                        if let speed = value.as(Double.self) {
                            AxisValueLabel {
                                Text(formatSpeed(speed, useMB: useMB))
                                    .font(.system(size: 9))
                                    .foregroundColor(.secondary)
                            }
                        }
                    }
                }
                .chartYScale(domain: 0...(max(peakKBs * 1.15, 1.0)))
                .chartLegend(.hidden)
                .chartOverlay { proxy in
                    GeometryReader { geo in
                        Rectangle().fill(.clear).contentShape(Rectangle())
                            .gesture(
                                DragGesture(minimumDistance: 0)
                                    .onChanged { drag in
                                        let origin = geo[proxy.plotAreaFrame].origin
                                        let locationX = drag.location.x - origin.x
                                        if let date: Date = proxy.value(atX: locationX) {
                                            ruleMark = date
                                            selectedEntry = entries.min(by: {
                                                abs($0.timestamp.timeIntervalSince(date)) < abs($1.timestamp.timeIntervalSince(date))
                                            })
                                        }
                                    }
                                    .onEnded { _ in
                                        withAnimation(.easeOut(duration: 0.3)) {
                                            ruleMark = nil
                                            selectedEntry = nil
                                        }
                                    }
                            )
                    }
                }
                .frame(height: 200)
            }

            // Selection detail tooltip
            if let entry = selectedEntry {
                HStack(spacing: 16) {
                    HStack(spacing: 6) {
                        Circle().fill(Color.blue).frame(width: 6, height: 6)
                        Text("Down: \(formatSpeed(entry.downloadKBs, useMB: useMB))")
                            .font(.system(.caption, design: .monospaced))
                            .foregroundColor(.blue)
                    }
                    HStack(spacing: 6) {
                        Circle().fill(Color.green).frame(width: 6, height: 6)
                        Text("Up: \(formatSpeed(entry.uploadKBs, useMB: useMB))")
                            .font(.system(.caption, design: .monospaced))
                            .foregroundColor(.green)
                    }
                    Spacer()
                    Text(formatTooltipTime(entry.timestamp))
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(RoundedRectangle(cornerRadius: 8)
                    .fill(Color(NSColor.controlBackgroundColor))
                    .shadow(color: .black.opacity(0.06), radius: 3, y: 1))
            }
        }
        .padding()
        .background(RoundedRectangle(cornerRadius: 12)
            .fill(Color(NSColor.controlBackgroundColor)))
    }

    // MARK: - Formatting

    private func formatSpeed(_ kbPerSec: Double, useMB: Bool) -> String {
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

    private func formatTooltipTime(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "h:mm:ss a"
        return formatter.string(from: date)
    }
}

// MARK: - Chart Data Entry

private struct ChartEntry: Identifiable {
    let timestamp: Date
    let downloadKBs: Double
    let uploadKBs: Double

    var id: TimeInterval { timestamp.timeIntervalSinceReferenceDate }
}
