import SwiftUI
import Charts

struct NetworkTrafficChart: View {
    let data: [NetworkTrafficPoint]
    let timeRange: TimeRange
    
    var body: some View {
        Chart {
            ForEach(data) { point in
                LineMark(
                    x: .value("Time", point.timestamp),
                    y: .value("Download", point.downloadSpeed)
                )
                .foregroundStyle(.blue)
                .interpolationMethod(.catmullRom)
                
                LineMark(
                    x: .value("Time", point.timestamp),
                    y: .value("Upload", point.uploadSpeed)
                )
                .foregroundStyle(.green)
                .interpolationMethod(.catmullRom)
            }
        }
        .chartXAxis {
            AxisMarks(values: .automatic) { value in
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
                }
            }
        }
        .chartYAxis {
            AxisMarks(position: .leading) { value in
                if let speed = value.as(Double.self) {
                    AxisValueLabel {
                        Text("\(speed, specifier: "%.1f") MB/s")
                    }
                }
            }
        }
        .chartLegend(position: .top, alignment: .leading) {
            HStack {
                Circle()
                    .fill(.blue)
                    .frame(width: 8, height: 8)
                Text("Download")
                
                Circle()
                    .fill(.green)
                    .frame(width: 8, height: 8)
                Text("Upload")
            }
        }
    }
} 