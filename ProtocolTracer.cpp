/*
* Copyright 2002-2019 Intel Corporation.
*
* This software is provided to you as Sample Source Code as defined in the accompanying
* End User License Agreement for the Intel(R) Software Development Products ("Agreement")
* section 1.L.
*
* This software and the related documents are provided as is, with no express or implied
* warranties, other than those that are expressly stated in the License.
*/

/*! @file
*  This file contains an ISA-portable PIN tool for tracing instructions
*/

#include "pin.H"
#include <iostream>
#include <fstream>
#include <string>
#include <stdlib>


using std::hex;
using std::dec;
using std::string;
using std::ios;
using std::endl;

string printList[] = {"getaddrinfo", "gethostbyname","gethostbyaddr","GetAddrInfoW", "InternetOpenA", "InternetOpenW",
						"InternetConnectA", "InternetConnectW", "HttpOpenRequestA", "HttpOpenRequestW", "HttpAddRequestHeadersA", 
						"HttpAddRequestHeadersW", "HttpSendRequestA", "HttpSendRequestW", "send", "WinHttpOpen", "WinHttpConnect", 
						"WinHttpOpenRequest", "WinHttpAddRequestHeaders", "WinHttpSendRequest","URLDownloadToFileA","URLDownloadToFileW","URLDownloadToFile" };

string Sprint[] = {"gethostbyname","gethostbyaddr","getaddrinfo", "URLDownloadToFileA", "URLDownloadToFile", "InternetOpenA", "InternetConnectA", "HttpOpenRequestA", "HttpAddRequestHeadersA", "HttpSendRequestA","send", "WinHttpSendRequest" };
string Wprint[] = {"GetAddrInfoW","InternetOpenW","InternetConnectW", "HttpOpenRequestW", "HttpAddRequestHeadersW","URLDownloadToFileW","HttpSendRequestW", "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest", "WinHttpAddRequestHeaders"};

//string ReadToString(ADDRINT target);
/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

std::ofstream ProtocolTracer;

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "calltrace.out", "specify trace file name");
KNOB<string> KnobTraceString(KNOB_MODE_WRITEONCE, "pintool", "s", "", "trace string");
//KNOB<string> KnobTargetName(KNOB_MODE_WRITEONCE, "pintool", "n", "", "File name");
KNOB<BOOL>   KnobPrintArgs(KNOB_MODE_WRITEONCE, "pintool", "a", "0", "print call arguments");

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
	ProtocolTracer << "This tool produces a call trace with arguments." << endl << endl;
	ProtocolTracer << KNOB_BASE::StringKnobSummary() << endl;
	return -1;
}

string invalid = "invalid_rtn";


/* ===================================================================== */
// 난독화되어있을 경우 IAT 에 있는 정보들이 unnamedImageEntryPoint로 표현
// 함수의 이름을 돌려줌
const string *Target2String(ADDRINT target)
{
	string name = RTN_FindNameByAddress(target);
	if (name == "")
	{
		return &invalid;
	}
	else if (name == ".text" || name == "unnamedImageEntryPoint")
	{
		return new string(StringFromAddrint(target)); // address format convert

	}
	else
		return new string(name);
}

// String-type Argument Function
string ReadToString(ADDRINT target) {
	ADDRINT Buffer;

	// Data Copy
	PIN_SafeCopy(&Buffer, (ADDRINT *)(target), sizeof(ADDRINT));
	string cstring;
	while (1) {
		char c = 0;
		if (PIN_SafeCopy(&c, (ADDRINT *)Buffer, 1) != 1)
			break;
		if (c == 0)
			break;
		if ((c == '\n') || (c == '\r\n') || (c == '\r') || (c == '!'))
			c = ' ';
		//if (byte(c) < '0x7F'
		cstring += c;
		Buffer += 1;
	}
	return cstring;
}

// Wchar* type Argument Function
string ReadToWChar(ADDRINT target) {
	ADDRINT Buffer;
	string cstring;
	string trash;

	PIN_SafeCopy(&Buffer, (ADDRINT *)(target), sizeof(ADDRINT));

	while (1) {
		char c = 0;
		char c_1 = 0;

		PIN_SafeCopy(&c, (ADDRINT *)Buffer, 1);
		
		// Buffer += 1;
		if (c == 0)
			break;
		if ((c == '\n') || (c == '\r\n') || (c == '\r') || (c == '!'))
		{
			c = ' ';
			cstring += c;
			Buffer += 1;
		}
		else
		{
			cstring += c;
			Buffer += 1;
		}
			
		PIN_SafeCopy(&c_1, (ADDRINT *)Buffer, 1);
		trash += c_1;
		Buffer += 1;
	}
	return cstring;
}


/* ===================================================================== */
VOID  do_call_args(ADDRINT ins, const string *s, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT esp)
{
	string apiName = *s;
	PIN_LockClient();

	// IMG_FindByAddress를 통해 받은 IMG Object IMG_Name을 통해 이미지 이름을 가져올 수 있음
	string img_name = IMG_Name(IMG_FindByAddress(ins)); // IMG_FindByAddress 현재 명령어가 속한 이미	지
	PIN_UnlockClient();

	// dll 이름만 필요한 경우 아래의 정규식을 통해 dll 이름만 가져올 수 있음
	string base_img_name = img_name.substr(img_name.find_last_of("/\\") + 1);

	// String type 5 argument outputs
	string argString1 = ReadToString(esp); // 
	string argString2 = ReadToString(esp + 4); // 
	string argString3 = ReadToString(esp + 8); // 
	string argString4 = ReadToString(esp + 12); // 
	string argString5 = ReadToString(esp + 16); // 

	// wchar* type 5 argument outputs
	string argWchar1 = ReadToWChar(esp);
	string argWchar2 = ReadToWChar(esp + 4);
	string argWchar3 = ReadToWChar(esp + 8);
	string argWchar4 = ReadToWChar(esp + 12);
	string argWchar5 = ReadToWChar(esp + 16);

	// 통신 관련 API 출력
	for (string strAPI : printList)
	{
		if (apiName == strAPI)
		{
			if ((apiName == "GetAddrInfoW") || (apiName == "InternetOpenW") || (apiName == "InternetConnectW") || (apiName == "HttpOpenRequestW") || (apiName == "HttpAddRequestHeadersW") || (apiName == "HttpSendRequestW") || (apiName == "WinHttpOpen") || (apiName == "WinHttpConnect") || (apiName == "WinHttpOpenRequest"))
			{
				ProtocolTracer << "ProtocolTracer!" << base_img_name << "!" << *s << "!";// << std::hex << arg0 << "!" << arg1 << "!" << arg2 << "!" << arg3 << "!" << arg4 << "!";
				ProtocolTracer << "Wchar!";
				if (argWchar1.empty())
				{
					ProtocolTracer << "(0) NULL!";
				}
				else
				{
					//method = Method_token(argWchar1, " ");
					ProtocolTracer << std::dec << "(" << argWchar1.length() << ") " << argWchar1 << "!";
				}
				////////////////////////////////////////////////
				if (argWchar2.empty())
				{
					ProtocolTracer << "(0) NULL!";
				}
				else
				{
					ProtocolTracer << std::dec << "(" << argWchar2.length() << ") " << argWchar2 << "!";
				}
				////////////////////////////////////////////////////////
				if (argWchar3.empty())
				{
					ProtocolTracer << "(0) NULL!";
				}
				else
				{
					ProtocolTracer << std::dec << "(" << argWchar3.length() << ") " << argWchar3 << "!";
				}
				////////////////////////////////////////////////////
				if (argWchar4.empty())
				{
					ProtocolTracer << "(0) NULL!";
				}
				else
				{
					ProtocolTracer << std::dec << "(" << argWchar4.length() << ") " << argWchar4 << "!";
				}
				/////////////////////////////////////////////////////////////
				if (argWchar5.empty())
				{
					ProtocolTracer << "(0) NULL" << endl;
				}
				else
				{
					ProtocolTracer << std::dec << "(" << argWchar5.length() << ") " << argWchar5 << endl;
				}
			}
			else
			{
				ProtocolTracer << "ProtocolTracer!" << base_img_name << "!" << *s << "!";//<< std::hex << arg0 << "!" << arg1 << "!" << arg2 << "!" << arg3 << "!" << arg4 << "!";
				ProtocolTracer << "String!";
				if (argString1.empty())
				{
					ProtocolTracer << "(0) NULL!";
				}
				else
				{
					ProtocolTracer << std::dec << "(" << argString1.length() << ") " << argString1 << "!";
				}
				////////////////////////////////////////////////
				if (argString2.empty())
				{
					ProtocolTracer << "(0) NULL!";
				}
				else
				{
					ProtocolTracer << std::dec << "(" << argString2.length() << ") " << argString2 << "!";
				}
				////////////////////////////////////////////////////////
				if (argString3.empty())
				{
					ProtocolTracer << "(0) NULL!";
				}
				else
				{
					ProtocolTracer << std::dec << "(" << argString3.length() << ") " << argString3 << "!";
				}
				////////////////////////////////////////////////////
				if (argString4.empty())
				{
					ProtocolTracer << "(0) NULL!";
				}
				else
				{
					ProtocolTracer << std::dec << "(" << argString4.length() << ") " << argString4 << "!";
				}
				/////////////////////////////////////////////////////////////
				if (argString5.empty())
				{
					ProtocolTracer << "(0) NULL" << endl;
				}
				else
				{
					ProtocolTracer << std::dec << "(" << argString5.length() << ") " << argString5 << endl;
				}
				//////////////////////////////////////////////////////////
			}
		}
		
	}

}

/* ===================================================================== */
//
VOID  do_call_args_indirect(ADDRINT ins, ADDRINT target, BOOL taken, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT esp)
{
	if (!taken) return;

	const string *s = Target2String(target);
	do_call_args(ins, s, arg0, arg1, arg2, arg3, arg4, esp);

	if (s != &invalid)
		delete s;
}

/* ===================================================================== */

VOID  do_call(const string *s)
{
	ProtocolTracer << *s << endl;
}

/* ===================================================================== */

VOID  do_call_indirect(ADDRINT target, BOOL taken)
{
	if (!taken) return;

	const string *s = Target2String(target);
	do_call(s);

	if (s != &invalid)
		delete s;
}

/* ===================================================================== */

VOID Trace(TRACE trace, VOID *v)
{
	// 교착상태 방지
	PIN_LockClient();
	IMG img = IMG_FindByAddress(TRACE_Address(trace));
	PIN_UnlockClient();

	const BOOL print_args = KnobPrintArgs.Value(); // 사용자 pin tool 사용시 -a 옵션 값 "0" 또는 "1" 사용 switch

												   // 추적 가능한 라이브러리 여부 확인
	if (IMG_Valid(img))
	{
		// BBL(Basic block: a single entrace, single exit sequence of instructions) : 한번 분기에 대한 명령어 모음
		//          추적할 첫번째 BBL    BBL 값이 있는지 Check    BBL_Next 다음 BBL
		for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
		{
			INS tail = BBL_InsTail(bbl); // BBL의 마지막

			if (INS_IsCall(tail)) // 디스어셈블코드에서 CALL 명령이 나오면 : ins가 Call 명령어이면
			{
				// Direct Call
				if (INS_IsDirectControlFlow(tail))
				{
					const ADDRINT target = INS_DirectControlFlowTargetAddress(tail);
					if (print_args)
					{
						INS_InsertPredicatedCall(tail, IPOINT_BEFORE, AFUNPTR(do_call_args),
							IARG_INST_PTR, // 현재 명령어의 주소 
							IARG_PTR, Target2String(target), // call 타겟 인자
							IARG_FUNCARG_CALLSITE_VALUE, 0, //call의 첫번째 인자
							IARG_FUNCARG_CALLSITE_VALUE, 1, //call의 두번째 인자
							IARG_FUNCARG_CALLSITE_VALUE, 2, //call의 세번째 인자
							IARG_FUNCARG_CALLSITE_VALUE, 3,
							IARG_FUNCARG_CALLSITE_VALUE, 4,
							IARG_REG_VALUE, REG_ESP, // 현재 ESP(스택 크기 조정 레지스터)
							IARG_END);
					}
					else
					{
						INS_InsertPredicatedCall(tail, IPOINT_BEFORE, AFUNPTR(do_call),
							IARG_PTR, Target2String(target), IARG_END);
					}

				}
				else // indirect call
				{
					// API명을 알고있을경우
					if (print_args) // arg 값을 프린트할 경우
					{
						INS_InsertCall(tail, IPOINT_BEFORE, AFUNPTR(do_call_args_indirect),
							IARG_INST_PTR,
							IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN,
							IARG_FUNCARG_CALLSITE_VALUE, 0,
							IARG_FUNCARG_CALLSITE_VALUE, 1,
							IARG_FUNCARG_CALLSITE_VALUE, 2,
							IARG_FUNCARG_CALLSITE_VALUE, 3,
							IARG_FUNCARG_CALLSITE_VALUE, 4,
							IARG_REG_VALUE, REG_ESP,
							IARG_END);
					}
					else
					{
						INS_InsertCall(tail, IPOINT_BEFORE, AFUNPTR(do_call_indirect),
							IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN, IARG_END);
					}
				}
			}
			else
			{

				RTN rtn = TRACE_Rtn(trace);
				// 루틴 추적 - RTN은 함수 실행시 호출할 함수들이다. 함수 관련 함수들이 있는곳
				// 외부라이브러리로 점프하여 추적, 프로그램이 호출하는 모든 함수가 나열
				if (RTN_Valid(rtn) && !INS_IsDirectControlFlow(tail) && ".plt" == SEC_Name(RTN_Sec(rtn)))
				{
					if (print_args)
					{
						INS_InsertCall(tail, IPOINT_BEFORE, AFUNPTR(do_call_args_indirect),
							IARG_INST_PTR,
							IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN,
							IARG_FUNCARG_CALLSITE_VALUE, 0,
							IARG_FUNCARG_CALLSITE_VALUE, 1,
							IARG_FUNCARG_CALLSITE_VALUE, 2,
							IARG_FUNCARG_CALLSITE_VALUE, 3,
							IARG_FUNCARG_CALLSITE_VALUE, 4,
							IARG_REG_VALUE, REG_ESP,
							IARG_END);
					}
					else
					{
						INS_InsertCall(tail, IPOINT_BEFORE, AFUNPTR(do_call_indirect),
							IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN, IARG_END);
					}
				}
			}
		}
	}
}

/* ===================================================================== */

VOID Fini(INT32 code, VOID *v)
{
	//ProtocolTracer << "# eof" << endl;

	ProtocolTracer.close();
}

/* ===================================================================== */
/* Main                                                                  */
/*	argc, argv are the entire command line : pin - t <toolname> -- ...   */
/* ===================================================================== */
int main(int argc, char *argv[])	
{
	PIN_InitSymbols();
	int num = argc;
	if (PIN_Init(argc, argv))
	{
		return Usage();
	}
	ProtocolTracer.open(KnobOutputFile.Value().c_str(), std::ios::binary);
	//ProtocolTracer << argv[num - 1] << endl;
	//ProtocolTracer << KnobTargetName.Value().c_str() << endl;
	ProtocolTracer << hex;
	ProtocolTracer.setf(ios::showbase);


	TRACE_AddInstrumentFunction(Trace, 0);

	PIN_AddFiniFunction(Fini, 0);

	PIN_StartProgram();

	return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
