
compilation process:
	the makefile and makefile.rules should be copied from: source/tools/SimpleTools to source/tools/Config
	the makefile.rules should be editted: TEST_TOOL_ROOTS := <all other tools> project
	under source/tools/SimpleTools run the command: make project.test
	the file project.so will be generated under source/tools/SimpleTools/obj-intel64
	
running:
	need to run the command:
		<pin_path>/pin -t project.so -prof -- ./bzip2 -k -f input.txt
		in hot-loops.csv file prints the invoked loops ascendingly according to its terget address.
		
		<pin_path>/pin -t project.so -opt X -- ./bzip2 -k -f input.txt
		all loops that meet our pattern are unrolled by X and their functions are translated to TC.
		
hot-loops.csv file format:
	1st column: function's name that include the loop
	2nd column: loops' target
	3nd column: direct backward conditional branch address

pattern:
	direct backward conditional branch address with compare operation between a register and a memory operand
	that set its condition.
	
submittors:
	Banan Osman 312335565
	Mohammad Massarwa 204635791 