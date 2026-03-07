import Foundation

class UpdateChecker: ObservableObject {
    static let shared = UpdateChecker()

    @Published var updateAvailable: Bool = false
    @Published var latestVersion: String = ""
    @Published var currentVersion: String = "2.0.0"
    @Published var releaseNotes: String = ""
    @Published var downloadURL: String = ""
    @Published var isChecking: Bool = false
    @Published var lastChecked: Date?
    @Published var errorMessage: String?

    // Configure this with your actual GitHub repo
    private let owner = "pincheleee"
    private let repo = "AdvancedPrivacyDashboard"

    private init() {}

    func checkForUpdates() {
        isChecking = true
        errorMessage = nil

        guard let url = URL(string: "https://api.github.com/repos/\(owner)/\(repo)/releases/latest") else {
            errorMessage = "Invalid URL"
            isChecking = false
            return
        }

        var request = URLRequest(url: url)
        request.setValue("application/vnd.github.v3+json", forHTTPHeaderField: "Accept")

        URLSession.shared.dataTask(with: request) { [weak self] data, response, error in
            DispatchQueue.main.async {
                guard let self = self else { return }
                self.isChecking = false
                self.lastChecked = Date()

                if let error = error {
                    self.errorMessage = error.localizedDescription
                    return
                }

                guard let data = data,
                      let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                    self.errorMessage = "Failed to parse response"
                    return
                }

                let tagName = (json["tag_name"] as? String ?? "")
                    .replacingOccurrences(of: "v", with: "")
                self.latestVersion = tagName
                self.releaseNotes = json["body"] as? String ?? ""

                if let assets = json["assets"] as? [[String: Any]],
                   let firstAsset = assets.first,
                   let browserURL = firstAsset["browser_download_url"] as? String {
                    self.downloadURL = browserURL
                }

                self.updateAvailable = self.isNewer(tagName, than: self.currentVersion)
            }
        }.resume()
    }

    private func isNewer(_ latest: String, than current: String) -> Bool {
        let latestParts = latest.split(separator: ".").compactMap { Int($0) }
        let currentParts = current.split(separator: ".").compactMap { Int($0) }

        for i in 0..<max(latestParts.count, currentParts.count) {
            let l = i < latestParts.count ? latestParts[i] : 0
            let c = i < currentParts.count ? currentParts[i] : 0
            if l > c { return true }
            if l < c { return false }
        }
        return false
    }

    func schedulePeriodicCheck(interval: TimeInterval = 86400) {
        Timer.scheduledTimer(withTimeInterval: interval, repeats: true) { [weak self] _ in
            self?.checkForUpdates()
        }
    }
}
