
compilation process:
	the makefile and makefile.rules should be copied from: source/tools/SimpleTools to source/tools/Config
	the makefile.rules should be editted: TEST_TOOL_ROOTS := <all other tools> ex4
	under source/tools/SimpleTools run the command: make ex4.test
	the file ex4.so will be generated under source/tools/SimpleTools/obj-intel64
	
running:
	need to run the command:
		<pin_path>/pin -t ex4.so -prof -- ./bzip2 -k -f input.txt
		the names of the routines will be printed in hot-routines.csv file starting with the most invoked routine.
		
		<pin_path>/pin -t ex4.so -inst -- ./bzip2 -k -f input.txt
		will translate the 10 hottest routines and run the program.
		and fallBackSort function will be translated and the required loop is unrolled by 4.
		
submittors:
	Banan Osman 312335565
	Mohammad Massarwa 204635791 