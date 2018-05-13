/*
 * main.cpp
 *
 *  Created on: May 1, 2018
 *      Author: banan
 */


/*
 * main.cpp
 *
 *  Created on: Apr 19, 2018
 *      Author: banan
 */
#include <list>
#include <map>
#include <vector>
#include <fstream>
#include <iostream>
#include <string>
#include <algorithm>

#include "pin.H"

using namespace std;

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
	ADDRINT loopAddrTar;
	unsigned countSeen;
	unsigned currCountSeen;
	unsigned countLoopInvoked;
	unsigned diffCount;
	unsigned lastItrNumb;
	rtn_ent* loopRtn;
}loop_ent;

typedef map<ADDRINT,loop_ent*>::iterator mapItr;
list<rtn_ent*> rtn_list;
map<ADDRINT,loop_ent*> loop_map;
map<ADDRINT,loop_ent*> loop_tmp_map;

/* ===================================================================== */
/* instrumentation function                                                    */
/* ===================================================================== */
VOID doCount(unsigned* counter)
{
	(*counter)++;
}

VOID compareAndUpdate(loop_ent* loopInfo)
{
	loopInfo->countLoopInvoked++;
	if(loopInfo->currCountSeen != loopInfo->lastItrNumb)
	{
		(loopInfo->diffCount)++;
		loopInfo->lastItrNumb = loopInfo->currCountSeen;
	}
	loopInfo->currCountSeen = 0;
}

VOID doDoubleCount(unsigned* count1, unsigned* count2)
{
	(*count1)++;
	(*count2)++;
}

/* ===================================================================== */
/* PIN wrapper                                                    */
/* ===================================================================== */
VOID rtnWrapper(RTN rtn, VOID* v)
{
	rtn_ent* rtnInfo = new rtn_ent;
	rtnInfo->rtnName = RTN_Name(rtn);
	rtnInfo->rtnAddr = RTN_Address(rtn);
	rtnInfo->rtnInvCount = 0;

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
					loopInfo->diffCount = 0;
					loopInfo->lastItrNumb = 0;
					loopInfo->currCountSeen = 0;
					loopInfo->loopRtn = rtnInfo;

					loop_map.insert(pair<ADDRINT,loop_ent*>(INS_Address(ins),loopInfo));
				}

				it = loop_map.find(INS_Address(ins));
				INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)doDoubleCount, IARG_PTR, &it->second->countSeen, 
									IARG_PTR, &it->second->currCountSeen, IARG_END);
				INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)compareAndUpdate, IARG_PTR, it->second, IARG_END);
			} 
		} else if(INS_IsRet(ins))
		{
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)doCount, IARG_PTR, &rtnInfo->rtnInvCount , IARG_END);
		}
	}
	RTN_Close(rtn);
}

/* ===================================================================== */
/* Fini                                                                */
/* ===================================================================== */
bool compare(loop_ent* loop1, loop_ent* loop2)
{
	return (loop1->countSeen > loop2->countSeen);
}

VOID Fini(INT32 code, VOID *v)
{
	ofstream outFile;
	outFile.open("loop-count.csv");
	vector <loop_ent*> loop_vec;

   	 for( mapItr it = loop_map.begin(); it != loop_map.end(); ++it )
   	 {
    		loop_vec.push_back( it->second );
   	 }
	 sort(loop_vec.begin(),loop_vec.end(),compare);

	for(vector<loop_ent*>::iterator it=loop_vec.begin(); it!=loop_vec.end(); ++it)
	{
		if( (*it)->countSeen != 0)
		{
			outFile << "0x" << hex << (*it)->loopAddrTar<< ","
				<< dec <<(*it)->countSeen << ","
				<< dec <<(*it)->countLoopInvoked << ",";
				if( (*it)->countLoopInvoked != 0)
				{
					outFile << dec <<(*it)->countSeen/(*it)->countLoopInvoked << ",";
					outFile << dec <<(*it)->diffCount-1 << ",";
				} else {
					outFile << dec <<(*it)->countSeen << ",";
					outFile << dec <<(*it)->diffCount << ",";
				}
			
			outFile << dec <<(*it)->loopRtn->rtnName << ","
				<< "0x" << hex <<(*it)->loopRtn->rtnAddr << ","
				<< dec << (*it)->loopRtn->rtnInvCount
			        << endl;
		}
		
	}


	outFile.close();
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This Pintool counts according to ascending order, a profile to all loops in program. " << endl;
    cerr << "for each loop prints: target address, iteration number, invokation number, the average iterations per invokation, the routine name that includes it, the routin's address and the ruotine invokations number!" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char * argv[])
{
    // Initialize symbol table code, needed for routine names
    PIN_InitSymbols();

    // Initialize pin
    if (PIN_Init(argc, argv))
    {
    		return Usage();
    }

    RTN_AddInstrumentFunction(rtnWrapper ,0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();

    return 0;

}

