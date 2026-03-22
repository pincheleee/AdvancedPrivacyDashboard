import SwiftUI

struct BlocklistManagementView: View {
    @ObservedObject private var importer = BlocklistImporter()
    @State private var blocklist: Set<String> = []
    @State private var searchText = ""
    @State private var newDomain = ""
    @State private var selectedSource: BlocklistImporter.BlocklistSource = .stevenBlack
    @State private var showAddSheet = false
    @State private var sourceInfos: [PersistenceManager.BlocklistSourceInfo] = []
    @State private var sortedDomains: [String] = []

    var body: some View {
        VStack(spacing: 0) {
            headerSection
            Divider()
            HStack(spacing: 0) {
                VStack(spacing: 0) {
                    importSection
                    Divider()
                    sourceManagementSection
                }
                .frame(width: 320)
                Divider()
                blocklistBrowser
            }
        }
        .task {
            let (loadedBlocklist, loadedSources) = await Task.detached {
                let bl = PersistenceManager.shared.loadBlocklist()
                let si = PersistenceManager.shared.getBlocklistSources()
                return (bl, si)
            }.value
            blocklist = loadedBlocklist
            sourceInfos = loadedSources
            refreshSortedDomains()
        }
        .sheet(isPresented: $showAddSheet) {
            addDomainSheet
        }
    }

    private var headerSection: some View {
        HStack {
            Text("Blocklist Management")
                .font(.largeTitle)
                .bold()

            Spacer()

            Text("\(blocklist.count) domains blocked")
                .foregroundColor(.secondary)

            Button(action: { showAddSheet = true }) {
                Label("Add Domain", systemImage: "plus")
            }
            .buttonStyle(.borderedProminent)
        }
        .padding()
    }

    private var importSection: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Import Blocklist")
                .font(.headline)

            ForEach(BlocklistImporter.BlocklistSource.allCases) { source in
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(source.rawValue)
                                .font(.subheadline)
                                .fontWeight(.medium)
                            Text(source.description)
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }

                        Spacer()

                        if source == .custom {
                            Button("Choose File") {
                                importer.importFromFile()
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.small)
                        } else {
                            Button("Import") {
                                importer.importFromURL(source: source)
                            }
                            .buttonStyle(.bordered)
                            .controlSize(.small)
                            .disabled(importer.isImporting)
                        }
                    }
                }
                .padding(10)
                .background(RoundedRectangle(cornerRadius: 8)
                    .fill(Color(NSColor.controlBackgroundColor)))
            }

            if importer.isImporting {
                HStack {
                    ProgressView()
                        .scaleEffect(0.7)
                    Text(importer.importStatus)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            } else if !importer.importStatus.isEmpty {
                HStack {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundColor(.green)
                    Text(importer.importStatus)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                .task {
                    let (loadedBlocklist, loadedSources) = await Task.detached {
                        let bl = PersistenceManager.shared.loadBlocklist()
                        let si = PersistenceManager.shared.getBlocklistSources()
                        return (bl, si)
                    }.value
                    blocklist = loadedBlocklist
                    sourceInfos = loadedSources
                    refreshSortedDomains()
                }
            }

            Spacer()
        }
        .padding()
    }

    // MARK: - Source Management

    private var sourceManagementSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Active Sources")
                .font(.headline)

            if sourceInfos.isEmpty {
                Text("No blocklist sources imported yet.")
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .padding(.vertical, 8)
            } else {
                ForEach(sourceInfos, id: \.source) { info in
                    HStack(spacing: 8) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(info.source)
                                .font(.caption)
                                .fontWeight(.medium)
                                .lineLimit(1)
                            Text("\(info.domainCount) domains")
                                .font(.caption2)
                                .foregroundColor(.secondary)
                            Text("Last: \(info.lastImported)")
                                .font(.caption2)
                                .foregroundColor(.secondary)
                        }

                        Spacer()

                        Button(action: {
                            let source = info.source
                            Task {
                                let (loadedBlocklist, loadedSources) = await Task.detached {
                                    PersistenceManager.shared.removeBlocklistSource(source)
                                    let bl = PersistenceManager.shared.loadBlocklist()
                                    let si = PersistenceManager.shared.getBlocklistSources()
                                    return (bl, si)
                                }.value
                                blocklist = loadedBlocklist
                                sourceInfos = loadedSources
                                refreshSortedDomains()
                            }
                        }) {
                            Image(systemName: "trash")
                                .foregroundColor(.red)
                                .font(.caption)
                        }
                        .buttonStyle(.plain)
                        .help("Remove all domains from this source")
                    }
                    .padding(8)
                    .background(RoundedRectangle(cornerRadius: 6)
                        .fill(Color(NSColor.controlBackgroundColor)))
                }
            }
        }
        .padding()
    }

    private var filteredDomains: [String] {
        if searchText.isEmpty { return sortedDomains }
        let query = searchText
        return sortedDomains.filter { $0.localizedCaseInsensitiveContains(query) }
    }

    private func refreshSortedDomains() {
        sortedDomains = blocklist.sorted()
    }

    private var blocklistBrowser: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Blocked Domains")
                    .font(.headline)
                Spacer()
                TextField("Search domains...", text: $searchText)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 200)
            }

            if filteredDomains.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "shield.slash")
                        .font(.system(size: 40))
                        .foregroundColor(.secondary)
                    Text(searchText.isEmpty ? "No domains in blocklist" : "No matching domains")
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List {
                    ForEach(filteredDomains, id: \.self) { domain in
                        HStack {
                            Image(systemName: "xmark.circle.fill")
                                .foregroundColor(.red)
                                .font(.caption)
                            Text(domain)
                                .font(.system(.body, design: .monospaced))
                            Spacer()
                            Button(action: {
                                let d = domain
                                blocklist.remove(d)
                                refreshSortedDomains()
                                Task {
                                    await Task.detached {
                                        PersistenceManager.shared.removeBlocklistDomain(d)
                                    }.value
                                }
                            }) {
                                Image(systemName: "trash")
                                    .foregroundColor(.red)
                            }
                            .buttonStyle(.plain)
                        }
                    }
                }
            }
        }
        .padding()
    }

    private var addDomainSheet: some View {
        VStack(spacing: 16) {
            Text("Add Domain to Blocklist")
                .font(.headline)

            TextField("e.g. tracking.example.com", text: $newDomain)
                .textFieldStyle(.roundedBorder)

            HStack {
                Button("Cancel") {
                    showAddSheet = false
                    newDomain = ""
                }
                .buttonStyle(.bordered)

                Button("Add") {
                    let domain = newDomain.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                    guard !domain.isEmpty, domain.contains(".") else { return }
                    blocklist.insert(domain)
                    refreshSortedDomains()
                    newDomain = ""
                    showAddSheet = false
                    Task {
                        let d = domain
                        await Task.detached {
                            PersistenceManager.shared.saveBlocklistDomain(d)
                        }.value
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(newDomain.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
        .padding(24)
        .frame(width: 360)
    }
}
