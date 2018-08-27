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
#define new_base_addr 0x500000

KNOB<BOOL> KnobInst(KNOB_MODE_WRITEONCE,    "pintool",
    "opt", "0", "Inst run");

KNOB<BOOL> KnobProf(KNOB_MODE_WRITEONCE,    "pintool",
    "prof", "0", "Prof run");
/* ===================================================================== */
/* Typedefs */
/* ===================================================================== */
// instruction map with an entry for each new instruction:
typedef struct {
	ADDRINT orig_ins_addr;
	ADDRINT orig_targ_addr;

	ADDRINT new_ins_addr;
	int new_targ_entry;
	bool hasNewTargAddr;

	char encoded_ins[XED_MAX_INSTRUCTION_BYTES];
	xed_iclass_enum_t iclass_enum;
	unsigned int size;
	int disp;

} instr_map_t;

// Tables of all candidate routines to be translated:
typedef struct {
	ADDRINT rtn_addr;
	USIZE rtn_size;
	int instr_map_entry;   // negative instr_map_entry means routine does not have a translation.
	bool isSafeForReplacedProbe;
} translated_rtn_t;

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */
std::ofstream* out = 0;

// For XED:
#if defined(TARGET_IA32E)
    xed_state_t dstate = {XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b};
#else
    xed_state_t dstate = { XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b};
#endif

//For XED: Pass in the proper length: 15 is the max. But if you do not want to
//cross pages, you can pass less than 15 bytes, of course, the
//instruction might not decode if not enough bytes are provided.
const unsigned int max_inst_len = XED_MAX_INSTRUCTION_BYTES;

ADDRINT lowest_sec_addr = 0;
ADDRINT highest_sec_addr = 0;

map <ADDRINT,int*> lp_jmps;
int imp_points[3];

#define MAX_PROBE_JUMP_INSTR_BYTES  14

// tc (translation $) containing the new code:
char *tc;
int tc_cursor = 0;

//array for data about the instructions in image
instr_map_t *instr_map = NULL;
int num_of_instr_map_entries = 0;
int max_ins_count = 0;

// total number of routines in the main executable module:
int max_rtn_count = 0;

//array for data about the routines in image
translated_rtn_t *translated_rtn;
int translated_rtn_num = 0;

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

/************************/
/* dump_instr_from_mem */
/************************/
void dump_instr_from_mem (ADDRINT *address, ADDRINT new_addr)
{
  char disasm_buf[2048];
  xed_decoded_inst_t new_xedd;

  xed_decoded_inst_zero_set_mode(&new_xedd,&dstate);

  xed_error_enum_t xed_code = xed_decode(&new_xedd, reinterpret_cast<UINT8*>(address), max_inst_len);

  BOOL xed_ok = (xed_code == XED_ERROR_NONE);
  if (!xed_ok){
	  cerr << "invalid opcode" << endl;
	  return;
  }


  xed_format_context(XED_SYNTAX_INTEL, &new_xedd, disasm_buf, 2048, static_cast<UINT64>(new_addr), 0, 0);

  cerr << "0x" << hex << new_addr << ": " << disasm_buf <<  endl;
}

/**************************/
/* dump_instr_map_entry */
/**************************/
void dump_instr_map_entry(int instr_map_entry)
{
	cerr << dec << instr_map_entry << ": ";
	cerr << " orig_ins_addr: " << hex << instr_map[instr_map_entry].orig_ins_addr;
	cerr << " new_ins_addr: " << hex << instr_map[instr_map_entry].new_ins_addr;
	cerr << " orig_targ_addr: " << hex << instr_map[instr_map_entry].orig_targ_addr;

	ADDRINT new_targ_addr;
	if (instr_map[instr_map_entry].new_targ_entry >= 0)
	{
		cerr<<"    has a new target   ";
		new_targ_addr = instr_map[instr_map[instr_map_entry].new_targ_entry].new_ins_addr;
	}else
	{
		cerr<<"    doesn't have a new target   "<<endl;
		new_targ_addr = instr_map[instr_map_entry].orig_targ_addr;
	}
	cerr <<"  new entry j: "<<dec<<instr_map[instr_map_entry].new_targ_entry;
	cerr << " new_targ_addr: " << hex << new_targ_addr;
	cerr << "    new instr:";
	dump_instr_from_mem((ADDRINT *)instr_map[instr_map_entry].encoded_ins, instr_map[instr_map_entry].new_ins_addr);
}

/*************/
/* dump_tc() */
/*************/
void dump_tc()
{
  char disasm_buf[2048];
  xed_decoded_inst_t new_xedd;
  ADDRINT address = (ADDRINT)&tc[0];
  unsigned int size = 0;

  while (address < (ADDRINT)&tc[tc_cursor]) {

      address += size;

	  xed_decoded_inst_zero_set_mode(&new_xedd,&dstate);

	  xed_error_enum_t xed_code = xed_decode(&new_xedd, reinterpret_cast<UINT8*>(address), max_inst_len);

	  BOOL xed_ok = (xed_code == XED_ERROR_NONE);
	  if (!xed_ok){
		  cerr << "invalid opcode" << endl;
		  return;
	  }

	  xed_format_context(XED_SYNTAX_INTEL, &new_xedd, disasm_buf, 2048, static_cast<UINT64>(address), 0, 0);

	  cerr << "0x" << hex << address << ": " << disasm_buf <<  endl;

	  size = xed_decoded_inst_get_length (&new_xedd);
  }
}

/****************************/
/*  dump_entire_instr_map() */
/****************************/
void dump_entire_instr_map()
{
	for (int i=0; i < num_of_instr_map_entries; i++) {
		for (int j=0; j < translated_rtn_num; j++) {
			if (translated_rtn[j].instr_map_entry == i) {

				RTN rtn = RTN_FindByAddress(translated_rtn[j].rtn_addr);

				if (rtn == RTN_Invalid()) {
					cerr << "Unknwon"  << ":" << endl;
				} else {
				  cerr << RTN_Name(rtn) << ":" << endl;
				}
			}
		}
		dump_instr_from_mem ((ADDRINT *)instr_map[i].new_ins_addr, instr_map[i].new_ins_addr);
	}
}

/*************************/
/* add_new_instr_entry() */
/*************************/
int add_new_instr_entry(xed_decoded_inst_t *xedd, ADDRINT pc, unsigned int size)
{

	// copy orig instr to instr map:
    ADDRINT orig_targ_addr = 0;

	if (xed_decoded_inst_get_length (xedd) != size) {
		cerr<<"size: "<<size<<endl;
		cerr<<"get len: "<<xed_decoded_inst_get_length (xedd)<<endl;
		cerr << "Invalid instruction decoding" << endl;
		return -1;
	}

    xed_uint_t disp_byts = xed_decoded_inst_get_branch_displacement_width(xedd);

	xed_int32_t disp = 0;

    if (disp_byts > 0) { // there is a branch offset.
      disp = xed_decoded_inst_get_branch_displacement(xedd);
	  orig_targ_addr = pc + xed_decoded_inst_get_length (xedd) + disp;
	}

	// Converts the decoder request to a valid encoder request:
	xed_encoder_request_init_from_decode (xedd);

    unsigned int new_size = 0;

	xed_error_enum_t xed_error = xed_encode (xedd, reinterpret_cast<UINT8*>(instr_map[num_of_instr_map_entries].encoded_ins), max_inst_len , &new_size);
	if (xed_error != XED_ERROR_NONE) {
		cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
		return -1;
	}

	// add a new entry in the instr_map:

	instr_map[num_of_instr_map_entries].orig_ins_addr = pc;
	instr_map[num_of_instr_map_entries].new_ins_addr = (ADDRINT)&tc[tc_cursor];  // set an initial estimated addr in tc
	instr_map[num_of_instr_map_entries].orig_targ_addr = orig_targ_addr;
   	instr_map[num_of_instr_map_entries].hasNewTargAddr = false;
	instr_map[num_of_instr_map_entries].new_targ_entry = -1;
	instr_map[num_of_instr_map_entries].size = new_size;
	instr_map[num_of_instr_map_entries].disp = disp;
    instr_map[num_of_instr_map_entries].iclass_enum = xed_decoded_inst_get_iclass(xedd);

	num_of_instr_map_entries++;

	// update expected size of tc:
	tc_cursor += new_size;

	if (num_of_instr_map_entries >= max_ins_count) {
		cerr << "out of memory for map_instr" << endl;
		return -1;
	}


    // debug print new encoded instr:
	if (KnobVerbose) {
		cerr << "    new instr:";
		dump_instr_from_mem((ADDRINT *)instr_map[num_of_instr_map_entries-1].encoded_ins, instr_map[num_of_instr_map_entries-1].new_ins_addr);
	}

	return new_size;
}

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

/***************************/
/* int copy_instrs_to_tc() */
/***************************/
int copy_instrs_to_tc()
{
	int cursor = 0;

	for (int i=0; i < num_of_instr_map_entries; i++) {

	  if ((ADDRINT)&tc[cursor] != instr_map[i].new_ins_addr) {
		  cerr << "ERROR: Non-matching instruction addresses: " << hex << (ADDRINT)&tc[cursor] << " vs. " << instr_map[i].new_ins_addr << endl;
	      return -1;
	  }

	  memcpy(&tc[cursor], &instr_map[i].encoded_ins, instr_map[i].size);

	  cursor += instr_map[i].size;
	}

	return 0;
}


/*************************************/
/* void commit_translated_routines() */
/*************************************/
inline void commit_translated_routines()
{
	// Commit the translated functions:
	// Go over the candidate functions and replace the original ones by their new successfully translated ones:

	for (int i=0; i < translated_rtn_num; i++) {

		//replace function by new function in tc

		if (translated_rtn[i].instr_map_entry >= 0) {

			if (translated_rtn[i].rtn_size > MAX_PROBE_JUMP_INSTR_BYTES && translated_rtn[i].isSafeForReplacedProbe) {

				RTN rtn = RTN_FindByAddress(translated_rtn[i].rtn_addr);

				//debug print:
				if (rtn == RTN_Invalid()) {
					cerr << "committing rtN: Unknown";
				} else {
					cerr << "committing rtN: " << RTN_Name(rtn);
				}
				cerr << " from: 0x" << hex << RTN_Address(rtn) << " to: 0x" << hex << instr_map[translated_rtn[i].instr_map_entry].new_ins_addr << endl;


				if (RTN_IsSafeForProbedReplacement(rtn)) {

					AFUNPTR origFptr = RTN_ReplaceProbed(rtn,  (AFUNPTR)instr_map[translated_rtn[i].instr_map_entry].new_ins_addr);

					if (origFptr == NULL) {
						cerr << "RTN_ReplaceProbed failed.";
					} else {
						cerr << "RTN_ReplaceProbed succeeded. ";
					}
					cerr << " orig routine addr: 0x" << hex << translated_rtn[i].rtn_addr
							<< " replacement routine addr: 0x" << hex << instr_map[translated_rtn[i].instr_map_entry].new_ins_addr << endl;

					dump_instr_from_mem ((ADDRINT *)translated_rtn[i].rtn_addr, translated_rtn[i].rtn_addr);
				}
			}
		}
	}
}

/**************************/
/* fix_rip_displacement() */
/**************************/
int fix_rip_displacement(int instr_map_entry)
{

	xed_decoded_inst_t xedd;
	xed_decoded_inst_zero_set_mode(&xedd,&dstate);

	xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), max_inst_len);
	if (xed_code != XED_ERROR_NONE) {
		cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << instr_map[instr_map_entry].new_ins_addr << endl;
		return -1;
	}

	unsigned int memops = xed_decoded_inst_number_of_memory_operands(&xedd);

	if (instr_map[instr_map_entry].orig_targ_addr != 0)  // a direct jump or call instruction.
		return 0;

	bool isRipBase = false;
	xed_reg_enum_t base_reg = XED_REG_INVALID;
	xed_int64_t disp = 0;
	for(unsigned int i=0; i < memops ; i++)   {
		base_reg = xed_decoded_inst_get_base_reg(&xedd,i);
		disp = xed_decoded_inst_get_memory_displacement(&xedd,i);

		if (base_reg == XED_REG_RIP) {
			isRipBase = true;
			break;
		}
	}

	if (!isRipBase)
		return 0;


	//xed_uint_t disp_byts = xed_decoded_inst_get_memory_displacement_width(xedd,i); // how many byts in disp ( disp length in byts - for example FFFFFFFF = 4
	xed_int64_t new_disp = 0;
	xed_uint_t new_disp_byts = 4;   // set maximal num of byts for now.

	unsigned int orig_size = xed_decoded_inst_get_length(&xedd);

	// modify rip displacement. use direct addressing mode:
	new_disp = instr_map[instr_map_entry].orig_ins_addr + orig_size + disp ;
	//todo: why 0?
	xed_encoder_request_set_base0 (&xedd, XED_REG_INVALID);

	//Set the memory displacement using a bit length
	xed_encoder_request_set_memory_displacement (&xedd, new_disp, new_disp_byts);

	unsigned int size = XED_MAX_INSTRUCTION_BYTES;
	unsigned int new_size = 0;

	// Converts the decoder request to a valid encoder request:
	xed_encoder_request_init_from_decode (&xedd);

	xed_error_enum_t xed_error = xed_encode (&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), size , &new_size);
	if (xed_error != XED_ERROR_NONE) {
		cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
		dump_instr_map_entry(instr_map_entry);
		return -1;
	}

	if (KnobVerbose) {
		dump_instr_map_entry(instr_map_entry);
	}
	return new_size;
}

/************************************/
/* fix_direct_br_call_to_orig_addr */
/************************************/
int fix_direct_br_call_to_orig_addr(int instr_map_entry)
{
	xed_decoded_inst_t xedd;
	xed_decoded_inst_zero_set_mode(&xedd,&dstate);

	xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), max_inst_len);
	if (xed_code != XED_ERROR_NONE) {
		cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << instr_map[instr_map_entry].new_ins_addr << endl;
		return -1;
	}

	xed_category_enum_t category_enum = xed_decoded_inst_get_category(&xedd);
	//todo: why not conditional branch?
	if (category_enum != XED_CATEGORY_CALL && category_enum != XED_CATEGORY_UNCOND_BR) {
		cerr << "ERROR: Invalid direct jump from translated code to original code in routine: "
			  << RTN_Name(RTN_FindByAddress(instr_map[instr_map_entry].orig_ins_addr)) << endl;
		dump_instr_map_entry(instr_map_entry);
		return -1;
	}

	// check for cases of direct jumps/calls back to the original target address:
	if (instr_map[instr_map_entry].new_targ_entry >= 0) {
		cerr << "ERROR: Invalid jump or call instruction" << endl;
		return -1;
	}

	unsigned int ilen = XED_MAX_INSTRUCTION_BYTES;
	unsigned int olen = 0;


	xed_encoder_instruction_t  enc_instr;

	ADDRINT new_disp = (ADDRINT)&instr_map[instr_map_entry].orig_targ_addr -
		               instr_map[instr_map_entry].new_ins_addr -
					   xed_decoded_inst_get_length (&xedd);

	if (category_enum == XED_CATEGORY_CALL)
			xed_inst1(&enc_instr, dstate, XED_ICLASS_CALL_NEAR, 64, xed_mem_bd(XED_REG_RIP, xed_disp(new_disp, 32), 64));

	if (category_enum == XED_CATEGORY_UNCOND_BR)
			xed_inst1(&enc_instr, dstate, XED_ICLASS_JMP, 64, xed_mem_bd(XED_REG_RIP, xed_disp(new_disp, 32), 64));

	xed_encoder_request_t enc_req;

	xed_encoder_request_zero_set_mode(&enc_req, &dstate);
	xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
	if (!convert_ok) {
		cerr << "conversion to encode request failed" << endl;
		return -1;
	}

	xed_error_enum_t xed_error = xed_encode(&enc_req, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), ilen, &olen);
	if (xed_error != XED_ERROR_NONE) {
		cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
	    dump_instr_map_entry(instr_map_entry);
        return -1;
    }

	// handle the case where the original instruction size is different from new encoded instruction:
	if (olen != xed_decoded_inst_get_length (&xedd)) {
		new_disp = (ADDRINT)&instr_map[instr_map_entry].orig_targ_addr - instr_map[instr_map_entry].new_ins_addr - olen;

		if (category_enum == XED_CATEGORY_CALL)
			xed_inst1(&enc_instr, dstate, XED_ICLASS_CALL_NEAR, 64, xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));

		if (category_enum == XED_CATEGORY_UNCOND_BR)
			xed_inst1(&enc_instr, dstate, XED_ICLASS_JMP, 64, xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));

		xed_encoder_request_zero_set_mode(&enc_req, &dstate);
		xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
		if (!convert_ok) {
			cerr << "conversion to encode request failed" << endl;
			return -1;
		}

		xed_error = xed_encode (&enc_req, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), ilen , &olen);
		if (xed_error != XED_ERROR_NONE) {
			cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
			dump_instr_map_entry(instr_map_entry);
			return -1;
		}
	}
	// debug prints:
	if (KnobVerbose) {
		dump_instr_map_entry(instr_map_entry);
	}

	instr_map[instr_map_entry].hasNewTargAddr = true;
	return olen;
}

/***********************************/
/* fix_direct_br_call_displacement */
/***********************************/
int fix_direct_br_call_displacement(int instr_map_entry)
{
	xed_decoded_inst_t xedd;
	xed_decoded_inst_zero_set_mode(&xedd,&dstate);

	xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), max_inst_len);
	if (xed_code != XED_ERROR_NONE) {
		cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << instr_map[instr_map_entry].new_ins_addr << endl;
		return -1;
	}

	xed_int32_t  new_disp = 0;
	unsigned int size = XED_MAX_INSTRUCTION_BYTES;
	unsigned int new_size = 0;


	xed_category_enum_t category_enum = xed_decoded_inst_get_category(&xedd);

	if (category_enum != XED_CATEGORY_CALL && category_enum != XED_CATEGORY_COND_BR && category_enum != XED_CATEGORY_UNCOND_BR) {
		cerr << "ERROR: unrecognized branch displacement" << endl;
		return -1;
	}

	// fix branches/calls to original target addresses:
	if (instr_map[instr_map_entry].new_targ_entry < 0) {
	   int rc = fix_direct_br_call_to_orig_addr(instr_map_entry);
	   return rc;
	}

	// fix branches/calls to not original target addresses:
	ADDRINT new_targ_addr;
	new_targ_addr = instr_map[instr_map[instr_map_entry].new_targ_entry].new_ins_addr;
	new_disp = (new_targ_addr - instr_map[instr_map_entry].new_ins_addr) - instr_map[instr_map_entry].size;

	//todo: why 4?
	xed_uint_t   new_disp_byts = 4; // num_of_bytes(new_disp);  ???

	// the max displacement size of loop instructions is 1 byte:
	xed_iclass_enum_t iclass_enum = xed_decoded_inst_get_iclass(&xedd);
	if (iclass_enum == XED_ICLASS_LOOP ||  iclass_enum == XED_ICLASS_LOOPE || iclass_enum == XED_ICLASS_LOOPNE) {
	  new_disp_byts = 1;
	}

	// the max displacement size of jecxz instructions is ???:
	xed_iform_enum_t iform_enum = xed_decoded_inst_get_iform_enum (&xedd);
	if (iform_enum == XED_IFORM_JRCXZ_RELBRb){
	  new_disp_byts = 1;
	}

	// Converts the decoder request to a valid encoder request:
	xed_encoder_request_init_from_decode (&xedd);

	//Set the branch displacement:
	xed_encoder_request_set_branch_displacement (&xedd, new_disp, new_disp_byts);

	xed_uint8_t enc_buf[XED_MAX_INSTRUCTION_BYTES];
	unsigned int max_size = XED_MAX_INSTRUCTION_BYTES;

	xed_error_enum_t xed_error = xed_encode (&xedd, enc_buf, max_size , &new_size);
	if (xed_error != XED_ERROR_NONE) {
		cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) <<  endl;
		char buf[2048];
		xed_format_context(XED_SYNTAX_INTEL, &xedd, buf, 2048, static_cast<UINT64>(instr_map[instr_map_entry].orig_ins_addr), 0, 0);
	    cerr << " instr: " << "0x" << hex << instr_map[instr_map_entry].orig_ins_addr << " : " << buf <<  endl;
  		return -1;
	}

	new_targ_addr = instr_map[instr_map[instr_map_entry].new_targ_entry].new_ins_addr;

	new_disp = new_targ_addr - (instr_map[instr_map_entry].new_ins_addr + new_size);  // this is the correct displacement.

	//Set the branch displacement:
	xed_encoder_request_set_branch_displacement (&xedd, new_disp, new_disp_byts);

	xed_error = xed_encode (&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), size , &new_size); // &instr_map[i].size
	if (xed_error != XED_ERROR_NONE) {
		cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
		dump_instr_map_entry(instr_map_entry);
		return -1;
	}

	//debug print of new instruction in tc:
	if (KnobVerbose) {
		dump_instr_map_entry(instr_map_entry);
	}
	return new_size;
}


/************************************/
/* fix_instructions_displacements() */
/************************************/
int fix_instructions_displacements()
{
   // fix displacemnets of direct branch or call instructions:

    int size_diff = 0;

	do {

		size_diff = 0;

		if (KnobVerbose) {
			cerr << "starting a pass of fixing instructions displacements: " << endl;
		}

		for (int i=0; i < num_of_instr_map_entries; i++) {

			instr_map[i].new_ins_addr += size_diff;

			int rc = 0;

			// fix rip displacement:
			rc = fix_rip_displacement(i);
			if (rc < 0)
				return -1;
			//invalid rip register and set a full address
			if (rc > 0) { // this was a rip-based instruction which was fixed.
				if (instr_map[i].size != (unsigned int)rc) {
				   size_diff += (rc - instr_map[i].size);
				   instr_map[i].size = (unsigned int)rc;
				}
				continue;
			}

			// check if it is a direct branch or a direct call instruction:
			if (instr_map[i].orig_targ_addr == 0) {
				continue;  // not a direct branch or a direct call instruction.
			}


			// fix instruction displacement:
			rc = fix_direct_br_call_displacement(i);
			if (rc < 0)
				return -1;

			if (instr_map[i].size != (unsigned int)rc) {
			   size_diff += (rc - instr_map[i].size);
			   instr_map[i].size = (unsigned int)rc;
			}

		}  // end int i=0; i ..
	} while (size_diff != 0);

   return 0;
 }

/************************************************/
/* void print_memops(xed_decoded_inst_t* xedd)  */
/************************************************/
void print_memops(xed_decoded_inst_t* xedd) 
{
    unsigned int i, memops = xed_decoded_inst_number_of_memory_operands(xedd);
    cerr << "Memory Operands" << endl;
    
    for( i=0;i<memops ; i++)   {
        xed_bool_t r_or_w = false;
        cerr << "  " << i << " ";
        if ( xed_decoded_inst_mem_read(xedd,i)) {
            cerr << "   read ";
            r_or_w = true;
        }
        if (xed_decoded_inst_mem_written(xedd,i)) {
            cerr << "written ";
            r_or_w = true;
        }
        if (!r_or_w) {
            cerr << "   agen "; // LEA instructions
        }
        xed_reg_enum_t seg = xed_decoded_inst_get_seg_reg(xedd,i);
        if (seg != XED_REG_INVALID) {
            cerr << "SEG= " << xed_reg_enum_t2str(seg) << " ";
        }
        xed_reg_enum_t base = xed_decoded_inst_get_base_reg(xedd,i);
        if (base != XED_REG_INVALID) {
            cerr << "BASE= " << setw(3) << xed_reg_enum_t2str(base) << "/" 
                 << setw(3)
                 <<  xed_reg_class_enum_t2str(xed_reg_class(base)) << " "; 

			if (!strcmp(xed_reg_enum_t2str(base),"RIP"))
				cerr << " (Accessing mem via RIP) " ;

        }
        xed_reg_enum_t indx = xed_decoded_inst_get_index_reg(xedd,i);
        if (i == 0 && indx != XED_REG_INVALID) {
            cerr << "INDEX= " << setw(3) << xed_reg_enum_t2str(indx)
                 << "/" <<  setw(3) 
                 << xed_reg_class_enum_t2str(xed_reg_class(indx)) << " ";
            if (xed_decoded_inst_get_scale(xedd,i) != 0) {
                // only have a scale if the index exists.
                cerr << "SCALE= " <<  xed_decoded_inst_get_scale(xedd,i) << " ";
            }
        }
        xed_uint_t disp_bits = xed_decoded_inst_get_memory_displacement_width(xedd,i);
        if (disp_bits) {
            cerr  << "DISPLACEMENT_BYTES= " << disp_bits << " ";
            xed_int64_t disp = xed_decoded_inst_get_memory_displacement(xedd,i);
            cerr << "0x" << hex << setfill('0') << setw(16) << disp << setfill(' ') << dec << " base10=" << disp;
        }
        
        cerr << " ASZ" << i << "=" << xed_decoded_inst_get_memop_address_width(xedd,i);
        cerr << endl;
    }
    cerr << "  MemopBytes = " << xed_decoded_inst_get_memory_operand_length(xedd,0) << endl;
}

int decode_cmp(INS insCmp,vector<xed_reg_enum_t>& regVec,vector<xed_int64_t>& offsetVec)
{
	ADDRINT addrCmp = INS_Address(insCmp);
	xed_decoded_inst_t xedd;
	xed_error_enum_t xed_code;

	//init all fields to zero and set the mode
	xed_decoded_inst_zero_set_mode(&xedd,&dstate);

	//decodes the instruction
	xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(addrCmp), max_inst_len);
	if (xed_code != XED_ERROR_NONE) {
		cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << addrCmp << endl;
		translated_rtn[translated_rtn_num].instr_map_entry = -1;
		return -1;
	}
	if(xed_decoded_inst_get_iclass(&xedd) != XED_ICLASS_CMP)
	{
		cerr<<"not the required pattern!"<<endl;
		return 1;
	}

	const xed_inst_t* xedi = xed_decoded_inst_inst(&xedd);
	unsigned int noperands = xed_inst_noperands(xedi);
	for(unsigned int i=0; i < noperands ; i++)
	{
	    const xed_operand_t* op = xed_inst_operand(xedi,i);
	    xed_operand_enum_t op_name = xed_operand_name(op);
	    cerr << i << " " << setw(6) << xed_operand_enum_t2str(op_name) << endl;

	    switch(op_name)
	    {
			case XED_OPERAND_MEM0:
			case XED_OPERAND_MEM1:
			{
				print_memops(&xedd);
				unsigned int memops = xed_decoded_inst_number_of_memory_operands(&xedd);
				cerr<<"number of memop: "<< memops<<endl;
				xed_int64_t disp = xed_decoded_inst_get_memory_displacement(&xedd,offsetVec.size());
				offsetVec.push_back(disp);
				break;
			}
			case XED_OPERAND_REG0:
			case XED_OPERAND_REG1:
			case XED_OPERAND_REG2:
			case XED_OPERAND_REG3:
			case XED_OPERAND_REG4:
			case XED_OPERAND_REG5:
			case XED_OPERAND_REG6:
			case XED_OPERAND_REG7:
			case XED_OPERAND_REG8:
			{
				xed_reg_enum_t reg = xed_decoded_inst_get_reg(&xedd, op_name);
				cerr << xed_operand_enum_t2str(op_name) << "=" << xed_reg_enum_t2str(reg)<<endl;
				if(reg !=  XED_REG_RFLAGS)
				{
					regVec.push_back(reg);
				}
				break;
			}
			default:
			{
				break;
			}
	    }
	}
	return 0;
}

int get_val(INS ins,xed_reg_enum_t reg,xed_int64_t* disp)
{
	xed_decoded_inst_t xedd;
	xed_error_enum_t xed_code;
	bool isReqReg = false;

	for(INS i= ins; INS_Valid(i); i = INS_Prev(i))
	{
		ADDRINT addr = INS_Address(i);
		cerr<<"checking: "<<hex<<addr<<endl;
		//init all fields to zero and set the mode
		xed_decoded_inst_zero_set_mode(&xedd,&dstate);
		//decodes the instruction
		xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(addr), max_inst_len);
		if (xed_code != XED_ERROR_NONE) {
			cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << addr << endl;
			translated_rtn[translated_rtn_num].instr_map_entry = -1;
			return -1;
		}
		cerr<<"iclass: "<<xed_iclass_enum_t2str(xed_decoded_inst_get_iclass(&xedd))<<endl;
		cerr<<"category: "<<xed_category_enum_t2str(xed_decoded_inst_get_category(&xedd))<<endl;
		if(xed_decoded_inst_get_iclass(&xedd) != XED_ICLASS_MOV)
		{
			disp = NULL;
			continue;
		}
		const xed_inst_t* xedi = xed_decoded_inst_inst(&xedd);
		unsigned int noperands = xed_inst_noperands(xedi);
		for(unsigned int j=0; j<noperands ; j++)
		{
		    const xed_operand_t* op = xed_inst_operand(xedi,j);
		    xed_operand_enum_t op_name = xed_operand_name(op);
		    xed_reg_enum_t new_reg = xed_decoded_inst_get_reg(&xedd, op_name);
		    cerr <<"BB "<< xed_operand_enum_t2str(op_name) << "=" << xed_reg_enum_t2str(new_reg)<<endl;
		    if(new_reg == reg)
		    {
		    	cerr<<"found req reg!"<<endl;
		    	isReqReg = true;
		    	break;
		    }
		}

		if(isReqReg)
		{
			cerr<<"reg is true!"<<endl;
			if(xed_decoded_inst_number_of_memory_operands(&xedd) == 0)
			{ //two regs
				for(unsigned int j=0; j < noperands ; j++)
				{
				    const xed_operand_t* op = xed_inst_operand(xedi,j);
				    xed_operand_enum_t op_name = xed_operand_name(op);
				    xed_reg_enum_t newReg = xed_decoded_inst_get_reg(&xedd, op_name);
				    if(newReg != reg)
				    {
				    	cerr<<"recursive!"<<endl;
				    	return get_val(i,newReg,disp);
				    }
				}
			} else
			{ // one reg and disp
				cerr<<"found disp!"<<endl;
				*disp = xed_decoded_inst_get_memory_displacement(&xedd,0);
				return 0;
			}
		}
	}
	cerr<<"end function!"<<endl;
	return -1;
}

/////////////////////////////////////////////////
/////////////////////////////////////////////////
int find_i_n(INS ins,vector<xed_int64_t>& offsetVec,xed_int64_t* i_off,xed_int64_t* n_off)
{
	i_off = NULL;
	n_off = NULL;
	xed_decoded_inst_t xedd;
	xed_error_enum_t xed_code;
	for(INS i= ins; INS_Valid(i); i = INS_Prev(i))
	{
		ADDRINT addr = INS_Address(i);
		cerr<<"checking: "<<hex<<addr<<endl;
		//init all fields to zero and set the mode
		xed_decoded_inst_zero_set_mode(&xedd,&dstate);
		//decodes the instruction
		xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(addr), max_inst_len);
		if (xed_code != XED_ERROR_NONE) {
			cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << addr << endl;
			translated_rtn[translated_rtn_num].instr_map_entry = -1;
			return -1;
		}
		cerr<<"iclass: "<<xed_iclass_enum_t2str(xed_decoded_inst_get_iclass(&xedd))<<endl;
		cerr<<"category: "<<xed_category_enum_t2str(xed_decoded_inst_get_category(&xedd))<<endl;
		if(xed_decoded_inst_get_iclass(&xedd) != XED_ICLASS_ADD && xed_decoded_inst_get_iclass(&xedd) != XED_ICLASS_SUB )
		{
			continue;
		}
		const xed_inst_t* xedi = xed_decoded_inst_inst(&xedd);
		unsigned int noperands = xed_inst_noperands(xedi);
		xed_reg_enum_t base_reg = XED_REG_INVALID;
		for(unsigned int j=0; j<noperands ; j++)
		{
		    //const xed_operand_t* op = xed_inst_operand(xedi,j);
		    //xed_operand_enum_t op_name = xed_operand_name(op);
		    //xed_reg_enum_t new_reg = xed_decoded_inst_get_reg(&xedd, op_name);
			base_reg = xed_decoded_inst_get_base_reg(&xedd,j);
			xed_int64_t disp = xed_decoded_inst_get_memory_displacement(&xedd,j);
			cerr<<"decode!!!    "<<xed_reg_enum_t2str(base_reg)<<endl;

		    //cerr <<"BB "<< xed_operand_enum_t2str(op_name) << "=" << xed_reg_enum_t2str(new_reg)<<endl;
			if (base_reg == XED_REG_RBP) {
				cerr<<"found RIP!"<<endl;
				if (disp == offsetVec[0])
				{
					cerr<<"1111111111111!"<<endl;
					*i_off = disp;
					*n_off = offsetVec[1];
					cerr<<"return!!"<<endl;
					return 0;
				}else if(disp == offsetVec[1])
				{
					cerr<<"2222222222222!"<<endl;
					*i_off = disp;
					*n_off = offsetVec[0];
					cerr<<"return!!"<<endl;
					return 0;
				}
			}
		}

	}
	cerr<<"end function!"<<endl;
	return -1;
}// end function

int find_params(INS insJmp,xed_int64_t* paramArr)
{
	INS insCmp = INS_Prev(insJmp);
	vector<xed_reg_enum_t> regVec;
	vector<xed_int64_t> offsetVec;

	int rc = decode_cmp(insCmp,regVec,offsetVec);
	if(rc < 0)
	{
		return -1;
	} else if (rc == 1)
	{
		return 1;
	}

	// two regs or one reg and offset
	cerr<<"regVec size: "<<regVec.size()<<endl;

	if(regVec.size()>1)
	{
		return 1;
	}
	xed_int64_t disp;
	if(get_val(INS_Prev(insCmp),regVec[0],&disp)<0)
	{
		cerr<<"didn't find the disp!"<<endl;
		return -1;
	}
	offsetVec.push_back(disp);

	for(unsigned int i=0; i<offsetVec.size();i++)
	{
//		cerr<<"offset "<<i<<": "<<offsetVec[i]<<endl;
		paramArr[i] = offsetVec[i];
	}
	//all offsets!
	//TODO: first offset n and the second is i
	/// new mohammad
	// assume we have the two offsets
//	if(find_i_n(INS_Prev(insCmp),offsetVec,paramArr+1,paramArr)<0)
//	{
//		cerr<<"something wrong with the find i,n !"<<endl;
//		return -1;
//	}

	cerr<<"i: "<<hex<<paramArr[1]<<" n:"<<hex<<paramArr[0]<<endl;

	return 0;
}

//return the size of the added instructions
//return -1 in case of error
int decode_extension(xed_int64_t* paramArr)
{
	xed_encoder_instruction_t enc_instr;
	xed_encoder_request_t enc_req;
	xed_decoded_inst_t xedd;
	xed_error_enum_t xed_code;
	//char encoded_ins[XED_MAX_INSTRUCTION_BYTES];
	int all_sizes = 0;

	for (int i=0; i<4; i++)
	{
		if(i == 0)
		{
			xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 32, xed_reg(XED_REG_EAX),
					xed_mem_bd(XED_REG_RBP, xed_disp(paramArr[1], 32), 32));
			imp_points[0] = num_of_instr_map_entries;
		} else if(i == 1)
		{
			//xed_inst2(&enc_instr, dstate, XED_ICLASS_MOV, 32, xed_reg(XED_REG_ESI),xed_mem_bd(XED_REG_RIP, xed_disp(-0x86c, 32), 32));
		xed_inst2(&enc_instr, dstate, XED_ICLASS_ADD, 32, xed_reg(XED_REG_EAX),xed_imm0(UNROLL_NUM,32));
		} else if(i == 2)
		{
			//xed_inst2(&enc_instr, dstate, XED_ICLASS_ADD, 32, xed_reg(XED_REG_ESI),xed_imm0(-4,32));
			xed_inst2(&enc_instr, dstate, XED_ICLASS_CMP, 32, xed_reg(XED_REG_EAX), xed_mem_bd(XED_REG_RBP,xed_disp(paramArr[0],32),32));
		}else if(i == 3)
		{
			//xed_inst2(&enc_instr, dstate, XED_ICLASS_CMP, 32, xed_reg(XED_REG_ESI), xed_reg(XED_REG_EAX));
			xed_inst1(&enc_instr, dstate, XED_ICLASS_JL, 64,xed_relbr(0,32));
		}//else if(i == 4)
		//{
			//xed_inst1(&enc_instr, dstate, XED_ICLASS_JL, 64,xed_relbr(0,32));
		//}
		xed_encoder_request_zero_set_mode(&enc_req, &dstate);
		// Converts the decoder request to a valid encoder request:
		xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
		if (!convert_ok)
		{
			cerr << "conversion to encode request failed" << endl;
			return -1;
		}
		unsigned int new_size;
		xed_error_enum_t xed_error = xed_encode(&enc_req, reinterpret_cast<UINT8*>(instr_map[num_of_instr_map_entries+1].encoded_ins), max_inst_len, &new_size);
		if (xed_error != XED_ERROR_NONE)
		{
			cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
			return -1;
		}
		xed_decoded_inst_zero_set_mode(&xedd,&dstate);

		xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[num_of_instr_map_entries+1].encoded_ins), max_inst_len);
		if (xed_code != XED_ERROR_NONE)
		{
			cerr << "ERROR: xed decode failed the new cmp!"<< endl;
			return -1;
		}

		new_size = xed_decoded_inst_get_length(&xedd);
		cerr<<"new_size: "<<new_size<<endl;
		int rc = add_new_instr_entry(&xedd,new_base_addr+all_sizes, new_size);
		if (rc < 0)
		{
			cerr << "ERROR: failed during instructon translation." << endl;
			translated_rtn[translated_rtn_num].instr_map_entry = -1;
			return -1;
		}

		all_sizes += new_size;

	}

	return all_sizes;
}

int encode_uncon_jmp_inst(int ExtSize)
{
	unsigned int olen = 0;
	int rc;
	unsigned int ilen = XED_MAX_INSTRUCTION_BYTES;
	xed_decoded_inst_t xedd;
	xed_error_enum_t xed_code;

	xed_encoder_instruction_t  enc_instr;
	xed_inst1(&enc_instr, dstate, XED_ICLASS_JMP, 64,xed_relbr(0,32) );

	xed_encoder_request_t enc_req;

	xed_encoder_request_zero_set_mode(&enc_req, &dstate);
	xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
	if (!convert_ok) {
		cerr << "conversion to encode request failed" << endl;
		return -1;
	}

	char encoded_ins[XED_MAX_INSTRUCTION_BYTES];
	xed_error_enum_t xed_error = xed_encode(&enc_req, reinterpret_cast<UINT8*>(&encoded_ins), ilen, &olen);
	if (xed_error != XED_ERROR_NONE) {
		cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
        return -1;
    }

	xed_decoded_inst_zero_set_mode(&xedd,&dstate);

	xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(encoded_ins), max_inst_len);
	if (xed_code != XED_ERROR_NONE) {
		cerr << "ERROR: xed decode failed the new cmp!"<< endl;
		return -1;
	}

	int InsSize = xed_decoded_inst_get_length(&xedd);
	rc = add_new_instr_entry(&xedd, new_base_addr +ExtSize, InsSize);
	if (rc < 0) {
		cerr << "ERROR: failed during instructon translation." << endl;
		translated_rtn[translated_rtn_num].instr_map_entry = -1;
		return -1;
	}

	return InsSize;
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

		INS loopStartIns, cmpIns;
		xed_int64_t paramArr[2];
		int ExtSize = 0, unrollCount = -1;
		bool add_extension = false, add_remenant = false, unrolling = true, add_ins = true;
	    // Open the RTN.
		cerr <<   "rtn name: " << RTN_Name(rtn) << " : " << dec << translated_rtn_num << endl;
	    RTN_Open( rtn );
        for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
        {
    		//debug print of orig instruction:
//			if (KnobVerbose) {
// 				cerr << "old instr: ";
//				cerr << "0x" << hex << INS_Address(ins) << ": " << INS_Disassemble(ins) <<  endl;
//				//xed_print_hex_line(reinterpret_cast<UINT8*>(INS_Address (ins)), INS_Size(ins));
//			}

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

			if(addr == AddrintFromString(startAddr))
			{
				cerr<<"first addr!"<<endl;
				loopStartIns = INS_Prev(ins);
				if(unrollCount < 0)
				{
					add_ins = false;
					unrollCount++;
				}
				if(add_extension)
				{
					cerr<<"add ext!"<<endl;
					if((ExtSize = decode_extension(paramArr))<0)
					{
						cerr << "Error: adding extension failed!" << endl;
						return -1;
					}
					unrollCount++;
					add_extension = false;
					lp_jmps.insert(pair<ADDRINT,int*>(INS_Address(INS_Next(loopStartIns)),new int[3]));
				}
			} else if ((addr == AddrintFromString(endAddr)) && (unrolling == true)) //jump addr
			{
				cerr<<"found jump!"<<endl;
				rc = find_params(ins,paramArr);
				if(rc == -1)
				{
					return -1;
				} else if(rc == 1)
				{
					cerr<<"rc 1"<<endl;
					break;
				}
				cmpIns = INS_Prev(ins);
				ins = loopStartIns;
				add_extension = true;
				unrolling = false;
				add_ins = true;
				continue;
			}

			if(addr == INS_Address(cmpIns) && unrollCount < UNROLL_NUM && (unrolling == false))
			{
				cerr<<"add count!"<<endl;
					ins = loopStartIns;
					unrollCount++;
					continue;
			}

			//Add instr into instr map:
			if(add_ins)
			{
				cerr<<"old addr: "<<addr<<endl;
				rc = add_new_instr_entry(&xedd, INS_Address(ins), INS_Size(ins));
				if (rc < 0) {
					cerr << "ERROR: failed during instructon translation." << endl;
					translated_rtn[translated_rtn_num].instr_map_entry = -1;
					break;
				}
			}

			if (addr == AddrintFromString(endAddr)) //jump addr
			{
				if(add_remenant == false)
				{
					cerr<<"add uncon jump!"<<endl;
					int tmp_size;
					if((tmp_size = encode_uncon_jmp_inst(ExtSize))< 0)
					{
						cerr<<"failed to encode unconditional jump!"<<endl;
						return -1;
					}
					imp_points[1] = num_of_instr_map_entries; // reminant start index
					ins = loopStartIns;
					add_remenant = true;
				} else
				{
					cerr<<"add imp points!"<<endl;
					add_remenant = false;
					imp_points[2] = num_of_instr_map_entries; // after reminant
					for(int i=0; i<3; i++)
					{
						lp_jmps[INS_Address(INS_Next(loopStartIns))][i] = imp_points[i];
						cerr<<"addr: "<<INS_Address(INS_Next(loopStartIns))<<" :"<<lp_jmps[INS_Address(INS_Next(loopStartIns))][i]<<endl;
					}
				}
			}
		} // end for INS...

		// Close the RTN.
		RTN_Close( rtn );

		translated_rtn_num++;
	} // end for rtn...
	inFile.close();

	return 0;
}

/*************************************************/
/* chain_all_direct_br_and_call_target_entries() */
/*************************************************/
int chain_all_direct_br_and_call_target_entries()
{
	bool jl = true, extension = false;

	for(map<ADDRINT,int*>::iterator itr=lp_jmps.begin(); itr!=lp_jmps.end(); itr++)
	{
		for (int i=0; i < num_of_instr_map_entries; i++)
		{
			//orig_targ_addr == 0 for non branch instructions
			if (i == itr->second[0])
			{
				extension = true;
			}
			//orig_targ_addr == 0 for non branch instructions
			if (instr_map[i].orig_targ_addr == 0)
				continue;

			if (instr_map[i].hasNewTargAddr)
				continue;

			ADDRINT tc_targ_addr = instr_map[i].new_ins_addr + instr_map[i].size + instr_map[i].disp;
			if((tc_targ_addr == instr_map[i].new_ins_addr + instr_map[i].size) && (instr_map[i].iclass_enum == XED_ICLASS_JL))
			{ // first jl
				instr_map[i].hasNewTargAddr = true;
				instr_map[i].new_targ_entry = itr->second[1];
				dump_instr_map_entry(i);
				continue;
			} else if (instr_map[i].iclass_enum == XED_ICLASS_JL && jl)
			{ //second jl
				instr_map[i].hasNewTargAddr = true;
				instr_map[i].new_targ_entry = itr->second[0];
				jl = false;
				dump_instr_map_entry(i);
				continue;
			}else if((tc_targ_addr == instr_map[i].new_ins_addr + instr_map[i].size) && (instr_map[i].iclass_enum == XED_ICLASS_JMP))
			{ //uncond jmp
				instr_map[i].hasNewTargAddr = true;
				instr_map[i].new_targ_entry = itr->second[2];
				dump_instr_map_entry(i);
						continue;
			}

			for (int j = 0; j < num_of_instr_map_entries; j++)
			{
				if (j == i)
				continue;

				if (extension && (instr_map[j].new_ins_addr == tc_targ_addr))
				{
						instr_map[i].hasNewTargAddr = true;
						instr_map[i].new_targ_entry = j;
						break;
				} else if ((extension == false) && (instr_map[j].orig_ins_addr == instr_map[i].orig_targ_addr))
				{
					instr_map[i].hasNewTargAddr = true;
		            instr_map[i].new_targ_entry = j;
	                break;
				}
			}
		}
	}

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
