
compilation process:
	the makefile and makefile.rules should be copied from: source/tools/SimpleTools to source/tools/Config
	the makefile.rules should be editted: TEST_TOOL_ROOTS := <all other tools> ex2
	under source/tools/SimpleTools run the command: maked ex2.test
	the file ex2.so will be generated under source/tools/SimpleTools/obj-intel64
	
running:
	need to run the command:
		<pin_path>/pin -t ex2.so -- ./bzip2 -k -f input.txt
		
		the results will be printed in loop-count.csv file
		

submittors:
	Banan Osman 312335565
	Mohammad Massarwa 204635791 