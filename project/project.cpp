#include "pin.H"
extern "C" {
#include "xed-interface.h"
}
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <values.h>

#include <list>
#include <map>
#include <cstring>
#include <algorithm>
#include <vector>
#include <fstream>
#include <iostream>

using namespace std;

/*======================================================================*/
/* commandline switches                                                 */
/*======================================================================*/
KNOB<BOOL>   KnobVerbose(KNOB_MODE_WRITEONCE,    "pintool",
    "verbose", "0", "Verbose run");

KNOB<BOOL>   KnobDumpTranslatedCode(KNOB_MODE_WRITEONCE,    "pintool",
    "dump_tc", "0", "Dump Translated Code");

KNOB<BOOL>   KnobDoNotCommitTranslatedCode(KNOB_MODE_WRITEONCE,    "pintool",
    "no_tc_commit", "0", "Do not commit translated code");

//TODO: how to get parameter
#define UNROLL_NUM 4
KNOB<BOOL> KnobInst(KNOB_MODE_WRITEONCE,    "pintool",
    "opt", "0", "Inst run");

KNOB<BOOL> KnobProf(KNOB_MODE_WRITEONCE,    "pintool",
    "prof", "0", "Prof run");

/* ===================================================================== */
/* struct define                                                     */
/* ===================================================================== */
typedef struct
{
	string rtnName;
	ADDRINT rtnAddr;
	unsigned rtnInvCount;
}rtn_ent;

typedef struct
{
	ADDRINT loopAddrJmp;
	ADDRINT loopAddrTar;
	unsigned countSeen;
	unsigned countLoopInvoked;
	rtn_ent* loopRtn;
}loop_ent;

typedef map<ADDRINT,loop_ent*>::iterator mapItr;
list<rtn_ent*> rtn_list;
map<ADDRINT,loop_ent*> loop_map;
/* ===================================================================== */
/* instrumentation function                                                    */
/* ===================================================================== */
VOID doCount(unsigned *counter)
{
	(*counter)++;
}

/* ===================================================================== */
/* Profiling routine                                                   */
/* ===================================================================== */
VOID rtnWrapper(RTN rtn, VOID *v)
{
	if (!IMG_IsMainExecutable(SEC_Img(RTN_Sec(rtn))))
		return;

	if (rtn == RTN_Invalid())
	{
		return;
	}
	rtn_ent* rtnInfo = new rtn_ent;
	rtnInfo->rtnName = RTN_Name(rtn);
	rtnInfo->rtnAddr = RTN_Address(rtn);
	rtn_list.push_back(rtnInfo);

	RTN_Open(rtn);
	for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
	{
		if(INS_IsDirectBranch(ins))
		{
			INT32 insCategory = INS_Category(ins);
			if((insCategory == XED_CATEGORY_COND_BR) &&
			   (INS_Address(ins) > INS_DirectBranchOrCallTargetAddress(ins)))
			{
				mapItr it = loop_map.find(INS_Address(ins));
				if(it == loop_map.end())
				{
					loop_ent* loopInfo = new loop_ent;
					loopInfo->loopAddrTar = INS_DirectBranchOrCallTargetAddress(ins);
					loopInfo->countSeen = 0;
					loopInfo->countLoopInvoked = 0;
					loopInfo->currCountSeen = 0;
					loopInfo->loopAddrJmp = INS_Address(ins);
					loopInfo->loopRtn = rtnInfo;

					loop_map.insert(pair<ADDRINT,loop_ent*>(INS_Address(ins),loopInfo));
				}

				it = loop_map.find(INS_Address(ins));
				INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)doCount, IARG_PTR, &it->second->countSeen, IARG_END);
				INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)doCount, IARG_PTR, &it->second->countLoopInvoked, IARG_END);
			}
		}
	}
	RTN_Close(rtn);
}

/* ===================================================================== */
/* Fini                                                                */
/* ===================================================================== */
bool compare(loop_ent* lp1, loop_ent* lp2)
{
	return (lp1->countSeen > lp2->countSeen);
}

VOID Fini(INT32 code, VOID *v)
{
	ofstream outFile;
	outFile.open("hot-loops.csv");
	vector <loop_ent*> loop_vec;
    for(mapItr it = loop_map.begin(); it != loop_map.end(); ++it )
    {
    	loop_vec.push_back(it->second);
	}
	sort(loop_vec.begin(),loop_vec.end(),compare);

	for(vector<loop_ent*>::iterator it=loop_vec.begin(); it!=loop_vec.end(); ++it)
	{
		if((*it)->countSeen != 0)
		{
			outFile << (*it)->loopRtn->rtnName << ",";
			outFile << (*it)->loopAddrTar << ",";
			outFile << (*it)->loopAddrJmp << ",";
			outFile << (*it)->countSeen << "," << endl;
		}
	}

	outFile.close();
}

/****************************/
/* allocate_and_init_memory */
/****************************/
int allocate_and_init_memory(IMG img)
{
	// Calculate size of executable sections and allocate required memory:
	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {
		//SEC_Address - if image loadable or not
		//todo: SEC_IsWriteable -
		if (!SEC_IsExecutable(sec) || SEC_IsWriteable(sec) || !SEC_Address(sec))
			continue;


		if (!lowest_sec_addr || lowest_sec_addr > SEC_Address(sec))
			lowest_sec_addr = SEC_Address(sec);

		if (highest_sec_addr < SEC_Address(sec) + SEC_Size(sec))
			highest_sec_addr = SEC_Address(sec) + SEC_Size(sec);

		// need to avouid using RTN_Open as it is expensive...
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {

			if (rtn == RTN_Invalid())
				continue;

			max_ins_count += RTN_NumIns(rtn);
			max_rtn_count++;
		}
	}

	max_ins_count *= 4; // estimating that the number of instructions of the in-lined functions will not exceed the total number of the entire code.

	// Allocate memory for the instr map needed to fix all branch targets in translated routines:
	instr_map = (instr_map_t *)calloc(max_ins_count, sizeof(instr_map_t));
	if (instr_map == NULL) {
		perror("calloc");
		return -1;
	}

	// Allocate memory for the array of candidate routines containing inlineable function calls:
	// Need to estimate size of inlined routines.. ???
	translated_rtn = (translated_rtn_t *)calloc(max_rtn_count, sizeof(translated_rtn_t));
	if (translated_rtn == NULL) {
		perror("calloc");
		return -1;
	}

	// get a page size in the system:
	int pagesize = sysconf(_SC_PAGE_SIZE);
    if (pagesize == -1) {
      perror("sysconf");
	  return -1;
	}

	ADDRINT text_size = (highest_sec_addr - lowest_sec_addr) * 2 + pagesize * 4;

    int tclen = 2 * text_size + pagesize * 4;   // need a better estimate???

	// Allocate the needed tc with RW+EXEC permissions and is not located in an address that is more than 32bits afar:
	char * addr = (char *) mmap(NULL, tclen, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if ((ADDRINT) addr == 0xffffffffffffffff) {
		cerr << "failed to allocate tc" << endl;
        return -1;
	}

	tc = (char *)addr;
	return 0;
}

int find_candidate_rtns_for_translation(IMG img)
{
    int rc;
    ifstream inFile;
    inFile.open("hot-loops.csv");
    string csvLoopInfo;
    for(int i=0; i<10; i++)
    {
    	getline(inFile,csvLoopInfo);
    	char* rtnName = strtok ((char*)csvLoopInfo.c_str(),",");
    	char* startAddr = strtok (NULL, ",");
    	char* endAddr = strtok (NULL, ",");
    	RTN rtn = RTN_FindByName(img, rtnName);
    	if (rtn == RTN_Invalid())
    	{
    		cerr << "Warning: invalid routine " << rtnName << endl;
    		continue;
    	}

    	// debug print of routine name:
    	if (KnobVerbose) {
    		cerr <<   "rtn name: " << RTN_Name(rtn) << " : " << dec << translated_rtn_num << endl;
    	}
			translated_rtn[translated_rtn_num].rtn_addr = RTN_Address(rtn);
			translated_rtn[translated_rtn_num].rtn_size = RTN_Size(rtn);
			translated_rtn[translated_rtn_num].instr_map_entry = num_of_instr_map_entries;
			translated_rtn[translated_rtn_num].isSafeForReplacedProbe = true;

	    // Open the RTN.
	    RTN_Open( rtn );
        for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
        {
    		//debug print of orig instruction:
			if (KnobVerbose) {
 				cerr << "old instr: ";
				cerr << "0x" << hex << INS_Address(ins) << ": " << INS_Disassemble(ins) <<  endl;
				//xed_print_hex_line(reinterpret_cast<UINT8*>(INS_Address (ins)), INS_Size(ins));
			}

			ADDRINT addr = INS_Address(ins);
			xed_decoded_inst_t xedd;
			xed_error_enum_t xed_code;

			//init all fields to zero and set the mode
			xed_decoded_inst_zero_set_mode(&xedd,&dstate);

			//decodes the instruction
			xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(addr), max_inst_len);
			if (xed_code != XED_ERROR_NONE) {
				cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << addr << endl;
				translated_rtn[translated_rtn_num].instr_map_entry = -1;
				break;
			}

			if((addr == AddrintFromString(startAddr)) && xed_decoded_inst_get_iclass(&xedd))
			{
				//start unrolling
			}

				// Add instr into instr map:
				rc = add_new_instr_entry(&xedd, INS_Address(ins), INS_Size(ins));
				if (rc < 0) {
					cerr << "ERROR: failed during instructon translation." << endl;
					translated_rtn[translated_rtn_num].instr_map_entry = -1;
					break;
				}
			} // end for INS...

			// Close the RTN.
			RTN_Close( rtn );

			translated_rtn_num++;
	} // end for rtn...
	inFile.close();

	return 0;
}

/* ============================================ */
/* Main translation routine                     */
/* ============================================ */
VOID ImageLoad(IMG img, VOID *v)
{
	// debug print of all images' instructions
	//dump_all_image_instrs(img);


    // Step 0: Check the image and the CPU:
	if (!IMG_IsMainExecutable(img))
		return;

	int rc = 0;

	// step 1: Check size of executable sections and allocate required memory:
	rc = allocate_and_init_memory(img);
	if (rc < 0)
		return;

	//array for data about instructions in image
	//array for data about routines in image
	//translation cache is allocated
	cout << "after memory allocation" << endl;


	// Step 2: go over all routines and identify candidate routines and copy their code into the instructions map IR:
	rc = find_candidate_rtns_for_translation(img);
	if (rc < 0)
		return;

	//update instructions and routines maps
	cout << "after identifying candidate routines" << endl;

	// Step 3: Chaining - calculate direct branch and call instructions to point to corresponding target instr entries:
	rc = chain_all_direct_br_and_call_target_entries();
	if (rc < 0 )
		return;

	//checked if target instructions are translated or not!
	cout << "after calculate direct br targets" << endl;

	// Step 4: fix rip-based, direct branch and direct call displacements:
	rc = fix_instructions_displacements();
	if (rc < 0 )
		return;

	//all displacement were fixed for branch, call and rip-based operations
	cout << "after fix instructions displacements" << endl;

	// Step 5: write translated routines to new tc:
	rc = copy_instrs_to_tc();
	if (rc < 0 )
		return;

	//instructions are copied to the translation cache
	cout << "after write all new instructions to memory tc" << endl;

   	if (KnobDumpTranslatedCode) {
	  	 cerr << "Translation Cache dump:" << endl;
       		 dump_tc();  // dump the entire tc

	   	cerr << endl << "instructions map dump:" << endl;
	   	dump_entire_instr_map();     // dump all translated instructions in map_instr
   	}


	// Step 6: Commit the translated routines:
	//Go over the candidate functions and replace the original ones by their new successfully translated ones:
	commit_translated_routines();

	cout << "after commit translated routines" << endl;
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */
INT32 Usage()
{
    cerr << "This tool translated routines of an Intel(R) 64 binary"
         << endl;
    cerr << KNOB_BASE::StringKnobSummary();
    cerr << endl;
    return -1;
}


/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
bool fexists(const char *filename)
{
  ifstream ifile(filename);
  return ifile;
}

int main(int argc, char * argv[])
{
    // Initialize pin & symbol manager
    //out = new std::ofstream("xed-print.out");

    if( PIN_Init(argc,argv))
        return Usage();

    PIN_InitSymbols();

   if(KnobInst)
    {
    	if(fexists("hot-loops.csv"))
    	{
    		// Register ImageLoad
    		IMG_AddInstrumentFunction(ImageLoad, 0);
    		// Start the program, never returns
    		PIN_StartProgramProbed();
    	}
    } else if(KnobProf)
    {
    	// Register ImageLoad
    	RTN_AddInstrumentFunction(rtnWrapper, 0);
    	PIN_AddFiniFunction(Fini, 0);
    	// Start the program, never returns
    	PIN_StartProgram();
    }else
    {
    	PIN_StartProgram();
    }

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
