import SwiftUI
import Charts

struct NetworkTrafficChart: View {
    let data: [NetworkTrafficPoint]
    let timeRange: TimeRange
    @State private var pulse = false

    // Use semantic colors that adapt to light/dark mode
    private let downloadColor: Color = .cyan
    private let uploadColor: Color = .green

    private var currentDownload: String {
        guard let last = data.last else { return "0.0 KB/s" }
        if last.downloadSpeed < 0.01 {
            return String(format: "%.1f KB/s", last.downloadSpeed * 1024)
        }
        return String(format: "%.2f MB/s", last.downloadSpeed)
    }

    private var currentUpload: String {
        guard let last = data.last else { return "0.0 KB/s" }
        if last.uploadSpeed < 0.01 {
            return String(format: "%.1f KB/s", last.uploadSpeed * 1024)
        }
        return String(format: "%.2f MB/s", last.uploadSpeed)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            // Material-style metric chips
            HStack(spacing: 10) {
                MetricChip(
                    label: "Download",
                    value: currentDownload,
                    color: downloadColor,
                    pulse: pulse
                )
                MetricChip(
                    label: "Upload",
                    value: currentUpload,
                    color: uploadColor,
                    pulse: pulse
                )
                Spacer()
            }

            // Chart
            Chart {
                ForEach(data) { point in
                    LineMark(
                        x: .value("Time", point.timestamp),
                        y: .value("Speed", point.downloadSpeed),
                        series: .value("Type", "Download")
                    )
                    .foregroundStyle(downloadColor)
                    .lineStyle(StrokeStyle(lineWidth: 2))
                    .interpolationMethod(.stepCenter)
                    .symbol {
                        if point.id == data.last?.id {
                            Circle()
                                .fill(downloadColor)
                                .frame(width: pulse ? 10 : 6, height: pulse ? 10 : 6)
                                .shadow(color: downloadColor.opacity(0.8), radius: pulse ? 10 : 3)
                        }
                    }

                    LineMark(
                        x: .value("Time", point.timestamp),
                        y: .value("Speed", point.uploadSpeed),
                        series: .value("Type", "Upload")
                    )
                    .foregroundStyle(uploadColor)
                    .lineStyle(StrokeStyle(lineWidth: 2))
                    .interpolationMethod(.stepCenter)
                    .symbol {
                        if point.id == data.last?.id {
                            Circle()
                                .fill(uploadColor)
                                .frame(width: pulse ? 10 : 6, height: pulse ? 10 : 6)
                                .shadow(color: uploadColor.opacity(0.8), radius: pulse ? 10 : 3)
                        }
                    }
                }
            }
            .chartLegend(.hidden)
            .chartPlotStyle { plot in
                plot
                    .background(
                        RoundedRectangle(cornerRadius: 12)
                            .fill(.ultraThinMaterial)
                    )
            }
            .chartXAxis {
                AxisMarks(values: .automatic) { value in
                    AxisGridLine(stroke: StrokeStyle(lineWidth: 0.5))
                        .foregroundStyle(Color.primary.opacity(0.08))
                    if let date = value.as(Date.self) {
                        AxisValueLabel {
                            switch timeRange {
                            case .hour:
                                Text(date, format: .dateTime.hour().minute())
                            case .day:
                                Text(date, format: .dateTime.hour())
                            case .week:
                                Text(date, format: .dateTime.weekday())
                            case .month:
                                Text(date, format: .dateTime.day())
                            }
                        }
                        .foregroundStyle(Color.secondary)
                        .font(.caption2)
                    }
                }
            }
            .chartYAxis {
                AxisMarks(position: .leading, values: .automatic(desiredCount: 4)) { value in
                    AxisGridLine(stroke: StrokeStyle(lineWidth: 0.5))
                        .foregroundStyle(Color.primary.opacity(0.08))
                    if let speed = value.as(Double.self) {
                        AxisValueLabel {
                            Text("\(speed, specifier: "%.1f")")
                        }
                        .foregroundStyle(Color.secondary)
                        .font(.caption2)
                    }
                }
            }
            .clipShape(RoundedRectangle(cornerRadius: 12))
        }
        .onAppear {
            withAnimation(.easeInOut(duration: 0.8).repeatForever(autoreverses: true)) {
                pulse = true
            }
        }
    }
}

struct MetricChip: View {
    let label: String
    let value: String
    let color: Color
    let pulse: Bool

    var body: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(color)
                .frame(width: 8, height: 8)
                .shadow(color: color.opacity(pulse ? 0.7 : 0.2), radius: pulse ? 4 : 1)

            VStack(alignment: .leading, spacing: 1) {
                Text(label)
                    .font(.caption2)
                    .foregroundColor(.secondary)
                Text(value)
                    .font(.system(.subheadline, design: .monospaced))
                    .fontWeight(.medium)
                    .foregroundColor(color)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(.ultraThinMaterial)
                .overlay(
                    RoundedRectangle(cornerRadius: 10)
                        .strokeBorder(color.opacity(0.15), lineWidth: 1)
                )
        )
    }
}
