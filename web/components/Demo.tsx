export default function Demo() {
  const usageExample = `# Basic Usage
$ ./loganalyser --help

# Analyze log file
$ ./loganalyser -f /path/to/logfile.log

# Real-time monitoring
$ ./loganalyser --live --source /var/log/

# Analyze with specific rules
$ ./loganalyser -f logfile.log -r rules/ttp_rules.txt`;

  return (
    <section id="demo" className="py-12 border-t border-gray-200 dark:border-gray-800">
      <div className="container mx-auto px-6 max-w-3xl">
        <h2 className="text-2xl md:text-3xl font-bold text-gray-900 dark:text-white mb-6">
          Demo
        </h2>
        
        {/* Video Embed */}
        <div className="aspect-video bg-gray-100 dark:bg-gray-900 border border-gray-300 dark:border-gray-800 rounded mb-8">
          <iframe
            className="w-full h-full rounded"
            src="https://www.youtube.com/embed/dQw4w9WgXcQ"
            title="Network Log Analyser Demo"
            allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
            allowFullScreen
          ></iframe>
        </div>

        {/* Usage Examples */}
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-3">
          Usage Examples
        </h3>
        <div className="bg-gray-100 dark:bg-gray-900 p-4 rounded font-mono text-xs border border-gray-300 dark:border-gray-800">
          <pre className="text-gray-800 dark:text-gray-300 overflow-x-auto leading-relaxed whitespace-pre">
{usageExample}
          </pre>
        </div>
      </div>
    </section>
  );
}
