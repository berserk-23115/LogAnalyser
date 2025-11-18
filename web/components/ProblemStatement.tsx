export default function ProblemStatement() {
  return (
    <section className="py-12 border-t border-gray-200 dark:border-gray-800">
      <div className="container mx-auto px-6 max-w-3xl">
        <h2 className="text-2xl md:text-3xl font-bold text-gray-900 dark:text-white mb-8">
          Problem Statement
        </h2>
        
        <div className="space-y-8">
          <div>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-3">
              Background
            </h3>
            <p className="text-sm text-gray-600 dark:text-gray-400 leading-relaxed">
              Continuous monitoring of systems and networks is extremely essential to detect, prevent, 
              and respond to cyber security threats. Security Operation Centre (SOC) plays an important 
              role for situational awareness of an organisation, where all logs are monitored continuously. 
              This provides a near real-time perception of threat landscape. However, in case of a scenario 
              where multiple isolated networks are to be monitored, it may be important to undertake this 
              activity in all isolated networks independently. The central monitoring may also be taken up 
              separately, only the logs are collected in the central location on regular intervals.
            </p>
          </div>

          <div>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-3">
              Detailed Description
            </h3>
            <ul className="space-y-2 text-sm text-gray-600 dark:text-gray-400">
              <li className="leading-relaxed">
                <span className="font-medium text-gray-900 dark:text-white">a)</span> Development of a portable self-oriented, fully functional log analysis tool to monitor 
                cyber security events on isolated networks.
              </li>
              <li className="leading-relaxed">
                <span className="font-medium text-gray-900 dark:text-white">b)</span> Configuration capability to prepare a light, informal, and efficient environment tailored 
                to the target IT infrastructure of isolated networks.
              </li>
              <li className="leading-relaxed">
                <span className="font-medium text-gray-900 dark:text-white">c)</span> Efficient detection of cyber security attacks based on malicious tactics, techniques, 
                and procedures (TTPs) signature, anomaly, heuristic, behavioral, rule-based analysis, 
                network traffic analysis, and threat intelligence feeds.
              </li>
              <li className="leading-relaxed">
                <span className="font-medium text-gray-900 dark:text-white">d)</span> Simple and efficient methodology to update the tool environment and necessary components 
                for keeping it current with evolving threats.
              </li>
            </ul>
          </div>

          {/* <div>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-3">
              Expected Solution
            </h3>
            <p className="text-sm text-gray-600 dark:text-gray-400 leading-relaxed mb-4">
              The solution should be a portable, easy-to-use log analysis tool capable of collecting, 
              parsing, and analysing logs from various system and network devices. It should function 
              without dependency on external cloud services, ensuring data privacy and flexibility across 
              different environments on isolated networks as well as central locations.
            </p>
            <div className="space-y-1 text-sm text-gray-600 dark:text-gray-400">
              <p><span className="font-medium text-gray-900 dark:text-white">Portability:</span> Easily deployable across Windows, Linux, and Mac</p>
              <p><span className="font-medium text-gray-900 dark:text-white">Multi-source Collection:</span> Support for Syslog, FTP, USB protocols</p>
              <p><span className="font-medium text-gray-900 dark:text-white">Log Parsing:</span> Handle multiple formats and normalization</p>
              <p><span className="font-medium text-gray-900 dark:text-white">Analysis:</span> Search, filter, and highlight key events</p>
              <p><span className="font-medium text-gray-900 dark:text-white">Interface:</span> Simple CLI for technical users</p>
              <p><span className="font-medium text-gray-900 dark:text-white">Offline:</span> No internet dependency required</p>
            </div>
          </div> */}
        </div>
      </div>
    </section>
  );
}
