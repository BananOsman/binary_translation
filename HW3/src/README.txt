
compilation process:
	the makefile and makefile.rules should be copied from: source/tools/SimpleTools to source/tools/Config
	the makefile.rules should be editted: TEST_TOOL_ROOTS := <all other tools> ex3
	under source/tools/SimpleTools run the command: maked ex3.test
	the file ex3.so will be generated under source/tools/SimpleTools/obj-intel64
	
running:
	need to run the command:
		<pin_path>/pin -t ex3.so -prof -- ./bzip2 -k -f input.txt
		the names of the routines will be printed in hot-routines.csv file starting with the most invoked routine.
		
		<pin_path>/pin -t ex3.so -inst -- ./bzip2 -k -f input.txt
		will translate the 10 hottest routines and run the program.
		
submittors:
	Banan Osman 312335565
	Mohammad Massarwa 204635791 