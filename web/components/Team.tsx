export default function Team() {
  const teamMembers = [
    "Anushk Kumar",
    "Abhas Gupta",
    "Arhan Jain",
    "Akshat Singh",
    "Ayush Kitnawat"
  ];

  return (
    <section className="py-12 border-t border-gray-200 dark:border-gray-800">
      <div className="container mx-auto px-6 max-w-3xl">
        <h2 className="text-2xl md:text-3xl font-bold text-gray-900 dark:text-white mb-6">
          Team
        </h2>
        
        <div className="grid md:grid-cols-2 gap-x-8 gap-y-2">
          {teamMembers.map((member, index) => (
            <div key={index} className="text-sm text-gray-600 dark:text-gray-400">
              {member}
            </div>
          ))})
        </div>
      </div>
    </section>
  );
}
