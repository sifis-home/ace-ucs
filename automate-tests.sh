#kill $(ps aux | grep "AceClient" | grep -v 'grep' | awk '{print $2}')
#kill $(ps aux | grep "AceRS" | grep -v 'grep' | awk '{print $2}')
#kill $(ps aux | grep "AceAS" | grep -v 'grep' | awk '{print $2}')

for i in {1..20}
do
	JAVA_HOME="/Library/Java/JavaVirtualMachines/jdk1.8.0_291.jdk/Contents/Home" mvn -Dexec.mainClass="se.sics.ace.performance.AceAS" -Dexec.classpathScope=test test-compile exec:java &
	sleep 4
	JAVA_HOME="/Library/Java/JavaVirtualMachines/jdk1.8.0_291.jdk/Contents/Home" mvn -o -Dexec.mainClass="se.sics.ace.performance.AceRS" -Dexec.classpathScope=test test-compile exec:java -Dexec.args="-o" &
	sleep 4 
	JAVA_HOME="/Library/Java/JavaVirtualMachines/jdk1.8.0_291.jdk/Contents/Home" mvn -Dexec.mainClass="se.sics.ace.performance.AceClient" -Dexec.classpathScope=test test-compile exec:java -Dexec.cleanupDaemonThreads=false -Dexec.args="-d 1" && fg
	kill $(ps aux | grep "AceRS" | grep -v 'grep' | awk '{print $2}')
	kill $(ps aux | grep "AceAS" | grep -v 'grep' | awk '{print $2}')
done
