//Chacha20 und Hex
#include "hex.h"
#include "secblock.h"
#include "files.h"
#include <string>
#include <chrono>
#include <ctime>  
#include <algorithm>

using namespace std;
using namespace spdlog;

LinuxVM* _linux;
SystemMonitor* _sm;
SSHHelper* _sshhelper;
ProcessCache* _pc;

char *enc_key_1_name = new char[100];

string _sshd_bin_path = "";
string _sshd_path = "";
string _profile = "";
string _ip = "";
int _bp_type = 0;
int key_extracted = 0;


vmi_pid_t _sshd_parent_pid = 0;

void ExtractDerivedKeys(addr_t key_1, addr_t key_2, vmi_instance_t vmi, vmi_pid_t pid);
bool FindSSHDParent();
static char int_to_char[] = {'A', 'B', 'C', 'D', 'E', 'F'};


static bool interrupted = false;
static void close_handler(int sig)
{
	get("console")->warn("Killing SSHKex");

	if (sig == SIGSEGV) 
	{
        cout << enc_key_1_name << endl;
        string str(enc_key_1_name);
        system(("python /root/read_files.py " + str).c_str());
        free(enc_key_1_name);

		_sm->GetBPM()->DeInit();
		_sm->Stop();
	}

	interrupted = true;
}

//this will work for one connection only, vector or struct need to be used.
addr_t ssh_addr = 0;

class SSHDoAuthentication : public EventListener
{
	public:
		bool callback(const Event* ev, void* data)
		{
			BPEventData* a = (BPEventData*) data;
			if(a->beforeSingleStep)
			{
				return false;
			}

			cout << "do auth" << endl;

			vmi_instance_t vmi = _sm->Lock();

			if(ssh_addr != 0)
			{
				const Process& p = _pc->GetProcessFromDtb(a->regs.cr3);
				vmi_pid_t pid = p.GetPid();

				addr_t state_addr = _sshhelper->GetAddrT(vmi, a->regs.cr3, ssh_addr + _sshhelper->session_state_in_ssh_offset);

				cout << hex << ssh_addr << endl;
				cout << hex << state_addr << endl;

				// char* temp = new char[200];
				// vmi_read_va(vmi, state_addr, pid, 200, temp, NULL);
				// cout << hexdumptostring(temp, 200) << endl;
				// delete[] temp;

				cout << "whatever : "<< dec << _sshhelper->newkeys_in_session_state_offset << endl;

				addr_t new_keys_addr_1 = _sshhelper->GetAddrT(vmi, a->regs.cr3, state_addr + _sshhelper->newkeys_in_session_state_offset);
                addr_t new_keys_addr_2 = _sshhelper->GetAddrT(vmi, a->regs.cr3, state_addr + _sshhelper->newkeys_in_session_state_offset + sizeof(addr_t));

                 cout << "new_keys" << hex << new_keys_addr_1 << endl;
                 cout << "new_keys" << hex << new_keys_addr_2 << endl;

                ExtractDerivedKeys(new_keys_addr_1, new_keys_addr_2, vmi, pid);
			}

			_sm->Unlock();

			return false;
		}
};
SSHDoAuthentication* sshDoAuthentication;

class KexDerivedStart : public EventListener
{
	public:
		bool callback(const Event* ev, void* data)
		{
			const ProcessBreakpointEvent* sev = dynamic_cast<const ProcessBreakpointEvent*>(ev);
			if(sev)
			{
				BPEventData* a = (BPEventData*) data;
				if(a->beforeSingleStep)
				{
					ssh_addr = (addr_t) a->regs.rdi;
					return false;
				}
			}

			return false;
		}
};
KexDerivedStart* kexDerivedStart;

int main(int argc, char* argv[]) 
{
	if (argc != 3)
	{
		cout << argv[0] << " <vmname> <setting json>" << endl;
		return -1;
	}

	struct sigaction act;
	act.sa_handler = close_handler;
	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);
	sigaction(SIGHUP, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	//sigaction(SIGSEGV, &act, NULL);
	sigaction(SIGALRM, &act, NULL);
	sigaction(SIGPIPE, &act, NULL);

	auto console = stdout_color_mt<spdlog::async_factory>("console");
	get("console")->info("Reading setting file");

	Setting setting(argv[2]);
	_sshd_bin_path = setting.GetStringValue("sshd_bin_path");
	_sshd_path = setting.GetStringValue("sshd_path");
	_profile = setting.GetStringValue("profile");
	_bp_type = setting.GetIntValue("bp_type");
	_ip = setting.GetStringValue("ip");

	get("console")->info("Setting up system monitor");

	SystemMonitor sm(argv[1], true);
	_sm = &sm;

	get("console")->info("Setting up breakpoint mechanism");

	if(_bp_type == 1)
	{
		Int3* int3 = new Int3(sm);
        sm.SetBPM(int3, int3->GetType());
        sm.Init();
    	int3->Init();

		get("console")->info("Int3 is used");
	}
	else if(_bp_type == 2 || _bp_type == 3)
	{
		Altp2mBasic* altp2mbasic = new Altp2mBasic(sm);
		sm.SetBPM(altp2mbasic, altp2mbasic->GetType());
		sm.Init();
		altp2mbasic->Init();

		get("console")->info("Basic Altp2m is used");
	}
	else
	{
		throw runtime_error("Wrong BP type");
	}

	get("console")->info("Setting up register mechanism");

	RegisterMechanism rm(sm);
	sm.SetRM(&rm);
	
	sm.Loop();

	LinuxVM linux(&sm);
	_linux = &linux;

	ProcessCache pc(linux);
	_pc = &pc;

	get("console")->info("Reading the debug symbol");

	SSHHelper sshhelper(_sshd_bin_path, _ip);
	sshhelper.GetOffsets();
	_sshhelper = &sshhelper;

    if(FindSSHDParent())
	{
		get("console")->info("Parent PID : {0:d}", _sshd_parent_pid);
		get("console")->info("[kex_derive_keys] VA : {0:x} PA : {1:x}", sshhelper.kex_derive_keys_va, sshhelper.kex_derive_keys_pa);
		get("console")->info("[do_authentiation2] VA : {0:x} PA : {1:x}", sshhelper.do_authentiation2_va, sshhelper.do_authentiation2_pa);

		kexDerivedStart = new KexDerivedStart();
		ProcessBreakpointEvent* kexDerivedBeginEvent = new ProcessBreakpointEvent("KexDerivedBeginListener", 0, sshhelper.kex_derive_keys_pa, *kexDerivedStart);
		sm.GetBPM()->InsertBreakpoint(kexDerivedBeginEvent);

		sshDoAuthentication = new SSHDoAuthentication();
		ProcessBreakpointEvent* sshDoAuthentication2Event = new ProcessBreakpointEvent("DoAuth2", 0, sshhelper.do_authentiation2_pa, *sshDoAuthentication);
		sm.GetBPM()->InsertBreakpoint(sshDoAuthentication2Event);
    }

	while(!interrupted) 
	{
		sleep(1);
	}

	linux.Stop();
	sm.Stop();

    return 0;
}


bool FindSSHDParent()
{
	vector<Process> processes = _linux->GetProcessList();
	for(vector<Process>::iterator it = processes.begin() ; it != processes.end(); ++it)
	{
		if((*it).GetName() == "sshd" && (*it).GetParentPid() == 1)
		{
			_sshd_parent_pid = (*it).GetPid();
			_sshhelper->GetAddresses(_linux, (*it));

			return true;
		}
	}

	return false;
}

void ExtractDerivedKeys(addr_t key_1, addr_t key_2, vmi_instance_t vmi, vmi_pid_t pid)
{

	addr_t enc_key_1_name_addr = 0;
	addr_t enc_key_2_name_addr = 0;
	vmi_read_va(vmi, key_1 + _sshhelper->enc_in_newkeys_offset + _sshhelper->name_in_enc_offset, pid, sizeof(addr_t), &enc_key_1_name_addr, NULL);
	vmi_read_va(vmi, key_2 + _sshhelper->enc_in_newkeys_offset + _sshhelper->name_in_enc_offset, pid, sizeof(addr_t), &enc_key_2_name_addr, NULL);

    cout << "enc_key_address: " << hex << enc_key_1_name_addr << endl;

    //Copy memeory address
    enc_key_1_name = vmi_read_str_va(vmi, enc_key_1_name_addr, pid);
	char* enc_key_2_name = vmi_read_str_va(vmi, enc_key_2_name_addr, pid);
	
	if (enc_key_1_name == NULL || enc_key_2_name == NULL)
		return;

	cout << enc_key_1_name << endl;
	cout << enc_key_2_name << endl;

	free(enc_key_2_name);

	u_int real_key_len = 0;
	vmi_read_va(vmi, key_1 + _sshhelper->enc_in_newkeys_offset + _sshhelper->key_len_in_enc_offset, pid, sizeof(u_int), &real_key_len, NULL);

    auto end = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(end);
    
    string keysavedir = std::ctime(&end_time);
    std::string::iterator end_pos = std::remove(keysavedir.begin(), keysavedir.end(), ' ');
    keysavedir.erase(end_pos, keysavedir.end());
    string OutputFolder = "/root/keys/";  
    if (!opendir(OutputFolder.c_str())) {
        cout << OutputFolder << endl;
        mkdir(OutputFolder.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);  
    }
    string keydir = OutputFolder + keysavedir;
    mkdir(keydir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
	for (int i = 1; i <= 6; i++)
	{
		addr_t newkeysaddr = 0;
		addr_t offset1 = 0;
		addr_t offset2 = 0;
		addr_t offset3 = 0;

		u_int key_len = 0;
		addr_t key_addr = 0;

		newkeysaddr = (i % 2 == 0) ? key_2 : key_1;
		offset1 = (i <= 4) ? _sshhelper->enc_in_newkeys_offset : _sshhelper->mac_in_newkeys_offset;
		offset2 = (i <= 2) ? _sshhelper->iv_len_in_enc_offset : (i <= 4) ? _sshhelper->key_len_in_enc_offset : _sshhelper->key_len_in_mac_offset;
		offset3 = (i <= 2) ? _sshhelper->iv_in_enc_offset : (i <= 4) ? _sshhelper->key_in_enc_offset : _sshhelper->key_in_mac_offset;

		vmi_read_va(vmi, newkeysaddr + offset1 + offset2, pid, sizeof(u_int), &key_len, NULL);
		vmi_read_va(vmi, newkeysaddr + offset1 + offset3, pid, sizeof(addr_t), &key_addr, NULL);

		//SecByteBlock keyByte[64];
		char* key = new char[real_key_len];
		unsigned char * keyByte = new unsigned char[64];;
		size_t count;
		vmi_read_va(vmi, key_addr, pid, real_key_len, key, NULL);
		vmi_read_va(vmi, key_addr, pid, real_key_len, keyByte, &count);

        vmi_read_va(vmi, key_addr, pid, real_key_len, key, NULL);

		cout << "key : " << int_to_char[i - 1] << " -- addr : " << hex << key_addr << " len : " << dec << key_len << " real len : " << real_key_len << endl;
		cout << "key : " << hexdumptostring(key, real_key_len) << endl;	
		cout << "Byte key : " << hex_encode(keyByte, key_len) << endl;
		//Write to file
		ofstream file;
        ofstream file2;
		stringstream ss;
        stringstream ss2;
		ss << keydir <<"/file_" << int_to_char[i-1] << ".txt";
        if (int_to_char[i-1] != 'E' || int_to_char[i-1] != 'F') {
	        ss2 << "/root/file_" << int_to_char[i-1] << ".txt";
        }
        file.open(ss.str());
        file2.open(ss2.str());
		file << hex_encode(keyByte, key_len);
        file2 << hex_encode(keyByte, key_len);
		file.close();
        file2.close();
		cout << "sizeof key : " << count << endl;
		
		delete[] key;
	}
    key_extracted = 1;

}
