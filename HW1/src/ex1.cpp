/*
 * main.cpp
 *
 *  Created on: Apr 19, 2018
 *      Author: banan
 */
#include <list>
#include <fstream>
#include <iostream>
#include <string>
#include <algorithm>
#include <cstring>

#include "pin.H"

using namespace std;

/* ===================================================================== */
/* struct define                                                     */
/* ===================================================================== */
typedef struct
{
	string rtnName;
	const char * imgName;
	ADDRINT rtnAddr;
	ADDRINT imgAddr;
	unsigned counter;
}rtn_ent;

list<rtn_ent*> rtn_list;

/* ===================================================================== */
/* instrumentation function                                                    */
/* ===================================================================== */
VOID doCount(unsigned* counter)
{
	(*counter)++;
}
/* ===================================================================== */
/* PIN wrapper                                                    */
/* ===================================================================== */
const char* getName(const char * path)
{
    const char * fileName = strrchr(path,'/');
    if (fileName)
        return fileName+1;
    else
        return path;
}

VOID rtnWrapper(RTN rtn, VOID* v)
{
	rtn_ent* rtnInfo = new rtn_ent;
	rtnInfo->rtnName = RTN_Name(rtn);
	rtnInfo->rtnAddr = RTN_Address(rtn);
	IMG img = SEC_Img(RTN_Sec(rtn));
	rtnInfo->imgName = getName(IMG_Name(img).c_str());
	rtnInfo->imgAddr = IMG_StartAddress(img);
	rtnInfo->counter = 0;

	rtn_list.push_back(rtnInfo);

	RTN_Open(rtn);
	for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
	{
	   INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)doCount, IARG_PTR, &(rtnInfo->counter), IARG_END);
	}
	RTN_Close(rtn);
}

/* ===================================================================== */
/* Fini                                                                */
/* ===================================================================== */
bool compare(rtn_ent* rtn1, rtn_ent* rtn2)
{
	return (rtn1->counter > rtn2->counter);
}

VOID Fini(INT32 code, VOID *v)
{
	ofstream outFile;
	outFile.open("rtn-output.csv");
	rtn_list.sort(compare);

	list<rtn_ent*>::iterator it;
	for(it=rtn_list.begin(); it!=rtn_list.end(); ++it)
	{
		if((*it)->counter > 0)
		{
		outFile << "0x" << hex << (*it)->imgAddr<< ","
				<< (*it)->imgName << ","
				<< "0x" << (*it)->rtnAddr << ","
				<< (*it)->rtnName << ","
				<< dec << (*it)->counter;
		outFile << endl;
		}
	}

	outFile.close();
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This Pintool counts the number of instructions executed in a routine" << endl;
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





