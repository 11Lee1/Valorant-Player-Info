#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <winhttp.h>
#include <cassert>
#include <fstream>
#include <codecvt>
#include <locale>
#include <string>
#include <initializer_list>
#include <utility>
#include <algorithm>
#include <vector>
#include <map>
#include <regex>
#include <format>
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/reader.h"
#include "riotapi.h"

#ifdef GetObject
#undef GetObject
#endif

_VALORANT_API_NAMESPACE_BEGIN
// no std::wstring_convert in C++20
template<typename _FromStrTy, typename _ToStrTy>
inline _ToStrTy ConvertString(const _FromStrTy& Str) {
	using _ToValueTy = _ToStrTy::value_type;
	using _FromValueTy = _FromStrTy::value_type;
	using _codecvtty = std::codecvt<_ToValueTy, _FromValueTy, std::mbstate_t>;

	const _codecvtty& FaceT = std::use_facet<_codecvtty>(std::locale());
	std::mbstate_t MBState = std::mbstate_t();

	const int CharsToAllocate = FaceT.length(
		MBState,
		Str.data(),
		Str.data() + Str.size(),
		Str.size()
	) + 1; // for zero

	std::unique_ptr<_ToValueTy[]> Data = std::make_unique<_ToValueTy[]>(CharsToAllocate);

	std::memset(Data.get(), 0, sizeof(_ToValueTy) * CharsToAllocate);

	const _FromValueTy* FromNext;
	_ToValueTy* ToNext;
	std::codecvt_base::result ConversionResult = FaceT.in(
		MBState,
		Str.data(),
		Str.data() + Str.size(),
		FromNext,
		Data.get(),
		Data.get() + CharsToAllocate,
		ToNext
	);

	if (ConversionResult != std::codecvt_base::ok)
		throw std::runtime_error("Failed code conversion");

	return _ToStrTy(Data.get());
}

std::wstring GetLocalAppdataPathW() {
	wchar_t LocalAppdataPathBuffer[MAX_PATH];
	std::size_t LocalAppdataPathRequiredCount = MAX_PATH;
	errno_t Error;

	Error = _wgetenv_s(
		&LocalAppdataPathRequiredCount,
		LocalAppdataPathBuffer,
		MAX_PATH,
		L"localappdata"
	);

	assert(!Error);

	return LocalAppdataPathBuffer;
}

std::string GetLocalAppdataPath() {
	char LocalAppdataPathBuffer[MAX_PATH];
	std::size_t LocalAppdataPathRequiredCount = MAX_PATH;
	errno_t Error;

	Error = getenv_s(
		&LocalAppdataPathRequiredCount,
		LocalAppdataPathBuffer,
		MAX_PATH,
		"localappdata"
	);
	assert(!Error);
	return LocalAppdataPathBuffer;
}

///////////////////////////////////////////////////
// CTime
///////////////////////////////////////////////////

CTime CTime::Now() {
	std::tm TM;
	__time64_t Time = _time64(nullptr);
	_gmtime64_s(&TM, &Time);
	return CTime(TM);
}

CTime CTime::NowLocal() {
	std::tm TM;
	__time64_t Time = _time64(nullptr);
	_localtime64_s(&TM, &Time);
	return CTime(TM);
}

CTime::CTime() : m_Time(0) {}

CTime::CTime(const __time64_t UnixTime) {
	m_Time = UnixTime;
}

CTime::CTime(const std::tm& Time) {
	std::tm T = Time;
	m_Time = _mktime64(&T);
}

CTime::CTime(const std::wstring& ISOTime) {
	std::tm T;

	int ParseCnt = swscanf_s(
		ISOTime.c_str(),
		L"%d-%d-%dT%d:%d:%dZ",
		&T.tm_year,
		&T.tm_mon,
		&T.tm_mday,
		&T.tm_hour,
		&T.tm_min,
		&T.tm_sec
	);

	if (ParseCnt != 6)
		throw std::invalid_argument("Invalid Time");

	T.tm_year -= 1900;
	T.tm_mon -= 1;
	T.tm_isdst = -1;

	m_Time = _mktime64(&T);
}

CTime::CTime(const std::string& ISOTime) {
	std::tm T;

	int ParseCnt = sscanf_s(
		ISOTime.c_str(),
		"%d-%d-%dT%d:%d:%dZ",
		&T.tm_year,
		&T.tm_mon,
		&T.tm_mday,
		&T.tm_hour,
		&T.tm_min,
		&T.tm_sec
	);

	if (ParseCnt != 6)
		throw std::invalid_argument("Invalid Time");

	T.tm_year -= 1900;
	T.tm_mon -= 1;
	T.tm_isdst = -1;

	m_Time = _mktime64(&T);
}

std::wstring CTime::GetISOFormatW() const {
	std::tm T;
	errno_t Error;

	Error = _localtime64_s(&T, &m_Time);

	assert(!Error);
	T.tm_year += 1900;
	T.tm_mon += 1;
	return std::vformat(
		L"{}-{}-{}T{}:{}:{}Z",
		std::make_wformat_args(
			T.tm_year,
			T.tm_mon,
			T.tm_mday,
			T.tm_hour,
			T.tm_min,
			T.tm_sec
		)
	);
}

std::string CTime::GetISOFormat() const {
	std::tm T;
	errno_t Error;

	Error = _localtime64_s(&T, &m_Time);

	assert(!Error);
	T.tm_year += 1900;
	T.tm_mon += 1;
	return std::vformat(
		"{}-{}-{}T{}:{}:{}Z",
		std::make_format_args(
			T.tm_year,
			T.tm_mon,
			T.tm_mday,
			T.tm_hour,
			T.tm_min,
			T.tm_sec
		)
	);
}

__time64_t CTime::GetUnix() const {
	return m_Time;
}

std::tm CTime::GetCTime() const {
	std::tm T;
	errno_t Error;

	Error = _localtime64_s(&T, &m_Time);
	assert(!Error);
	return T;
}

bool CTime::operator==(const CTime& Time) const {
	return m_Time == Time.m_Time;
}

bool CTime::operator>(const CTime& Time) const {
	return m_Time > Time.m_Time;
}

bool CTime::operator>=(const CTime& Time) const {
	return m_Time >= Time.m_Time;
}

bool CTime::operator<(const CTime& Time) const {
	return m_Time < Time.m_Time;
}

bool CTime::operator<=(const CTime& Time) const {
	return m_Time <= Time.m_Time;
}

////////////////////////////////////////
// WinHTTP
////////////////////////////////////////
typedef DWORD HTTPStatusCode;
#define HTTP_STATUSCODE_INVALID ((DWORD)0xFFFFFFFF)

struct HTTP_Response_t {
	bool RequestSent;
	bool ResponseRecieved;
	HTTPStatusCode StatusCode;
};

struct HTTPResource_t {
	HTTPResource_t() {}

	HTTPResource_t(const std::wstring& Path);

	HTTPResource_t(
		const std::initializer_list<std::wstring> Paths,
		const std::initializer_list<std::pair<std::wstring, std::wstring>> QueryKeyValuePairs = {}
	);

	std::wstring ToString() const;
	void AddPath(const std::wstring& Path);
	void AddPath(const std::initializer_list<std::wstring> Paths);
	void AddQuery(const std::wstring& Key, const std::wstring& Value);
	void AddQuery(const std::pair<std::wstring, std::wstring>& KeyValuePair);
	void AddQuery(const std::initializer_list<std::pair<std::wstring, std::wstring>> QueryKeyValuePairs);
	void SetFragment(const std::wstring& Fragment);
protected:
	const std::wstring& GetPathString() const;
	std::wstring GetQueryString() const;
	const std::wstring& GetFragmentString() const;
protected:
	std::wstring m_Resource;
	std::wstring m_Path;
	std::vector<std::wstring> m_Query;
	std::wstring m_Fragment;
};

class CHTTPConnection
{
public:
	CHTTPConnection();
	CHTTPConnection(const std::wstring& ServerAddress, INTERNET_PORT ServerPort = INTERNET_DEFAULT_PORT, const std::wstring& Agent = L"");
	~CHTTPConnection();
	HINTERNET GetServer();
	const HINTERNET GetServer() const;
protected:
	virtual void InitializeSession(const std::wstring& Agent = L"", DWORD dwFlags = WINHTTP_FLAG_SECURE_DEFAULTS);
	// server address can be a domain name or ip address
	virtual void EstablishConnectionToServer(const std::wstring& ServerAddress, INTERNET_PORT ServerPort = INTERNET_DEFAULT_PORT);
protected:
	HINTERNET m_hSession;
	HINTERNET m_hServer;
};

class CHTTPRequest
{
public:
	CHTTPRequest() = delete;
	~CHTTPRequest();

	CHTTPRequest(
		_In_ const CHTTPConnection& Connection,
		_In_ const std::wstring& Verb,
		_In_ const std::wstring& TargetResource,
		_In_ const DWORD dwFlags = WINHTTP_FLAG_SECURE
	);

	CHTTPRequest(
		_In_ const CHTTPConnection& Connection,
		_In_ const std::wstring& Verb,
		_In_ const HTTPResource_t& TargetResource,
		_In_ const DWORD dwFlags = WINHTTP_FLAG_SECURE
	);

	// Returns bytes written
	virtual DWORD WriteData(
		_In_reads_bytes_(DataSize) const void* pData,
		_In_ const DWORD DataSize
	);

	// returns true if successful
	// AdditionalDataSizeAfterRequestSent pretty much boils down to how much 
	// data you want to be able to write after you've sent the request
	virtual bool SendRequest(
		_In_reads_bytes_opt_(AdditionalHeadersSize) const wchar_t* pAdditionalHeaders,
		_In_opt_ const DWORD AdditionalHeadersSize,
		_In_reads_bytes_opt_(OptionalDataSize) void* pOptionalData,
		_In_opt_ const DWORD OptionalDataSize,
		_In_opt_ const DWORD AdditionalDataSizeAfterRequestSent = 0
	);

	// returns true if a resdponse is recieved
	virtual bool RecieveResponse();

	std::string ReadDataAvailable();
public:
	virtual DWORD GetStatusCode() const;
	// returns true if added successfully
	virtual bool AddHeader(const std::wstring& Header, DWORD dwModifiers = WINHTTP_ADDREQ_FLAG_ADD_IF_NEW);
	HINTERNET GetRequestHandle() const;
protected:
	HINTERNET m_hRequest;
};

////////////////////////////////////////
// HTTPResource_t
////////////////////////////////////////

HTTPResource_t::HTTPResource_t(const std::wstring& Path) {
	AddPath(Path);
}

HTTPResource_t::HTTPResource_t(
	const std::initializer_list<std::wstring> Paths,
	const std::initializer_list<std::pair<std::wstring, std::wstring>> QueryKeyValuePairs
) {
	AddPath(Paths);
	AddQuery(QueryKeyValuePairs);
}

std::wstring HTTPResource_t::ToString() const {
	return GetPathString() + GetQueryString() + GetFragmentString();
}

void HTTPResource_t::AddPath(const std::wstring& Path) {
	m_Path += L"/" + Path;
}

void HTTPResource_t::AddPath(const std::initializer_list<std::wstring> Paths) {
	for (const std::wstring& Path : Paths) {
		m_Path += L"/" + Path;
	}
}

void HTTPResource_t::AddQuery(const std::wstring& Key, const std::wstring& Value) {
	m_Query.emplace_back(Key + L"=" + Value);
}

void HTTPResource_t::AddQuery(const std::pair<std::wstring, std::wstring>& KeyValuePair) {
	AddQuery(KeyValuePair.first, KeyValuePair.second);
}

void HTTPResource_t::AddQuery(const std::initializer_list<std::pair<std::wstring, std::wstring>> QueryKeyValuePairs) {
	for (const std::pair<std::wstring, std::wstring>& KeyValuePair : QueryKeyValuePairs) {
		AddQuery(KeyValuePair);
	}
}

void HTTPResource_t::SetFragment(const std::wstring& Fragment) {
	m_Fragment = L"#" + Fragment;
}

const std::wstring& HTTPResource_t::GetPathString() const {
	return m_Path;
}

std::wstring HTTPResource_t::GetQueryString() const {
	if (m_Query.empty())
		return L"";

	std::wstring ReturnValue(L"?");

	std::for_each(
		m_Query.begin(),
		m_Query.end(),
		[&ReturnValue](const std::wstring& QueryParam) -> void {
			ReturnValue += L"&" + QueryParam;
		}
	);

	return ReturnValue;
}

const std::wstring& HTTPResource_t::GetFragmentString() const {
	return m_Fragment;
}

////////////////////////////////////////
// CHTTPConnection
////////////////////////////////////////

CHTTPConnection::CHTTPConnection() {
	m_hSession = NULL;
	m_hServer = NULL;
}

CHTTPConnection::CHTTPConnection(
	const std::wstring& ServerAddress,
	INTERNET_PORT ServerPort,
	const std::wstring& Agent
) {
	InitializeSession(Agent);
	EstablishConnectionToServer(ServerAddress, ServerPort);
}

CHTTPConnection::~CHTTPConnection() {
	WinHttpCloseHandle(m_hServer);
	WinHttpCloseHandle(m_hSession);
}

HINTERNET CHTTPConnection::GetServer() {
	return m_hServer;
}

const HINTERNET CHTTPConnection::GetServer() const {
	return m_hServer;
}

void CHTTPConnection::InitializeSession(const std::wstring& Agent, DWORD dwFlags) {
	m_hSession = WinHttpOpen(
		Agent.length() == 0 ? nullptr : Agent.c_str(),
		WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS,
		dwFlags
	);
}

// server address can be a domain name or ip address
void CHTTPConnection::EstablishConnectionToServer(const std::wstring& ServerAddress, INTERNET_PORT ServerPort) {
	assert(m_hSession);

	m_hServer = WinHttpConnect(
		m_hSession, // hSession
		ServerAddress.c_str(), // pswzServerName
		ServerPort, // nServerPort
		0 // Reserved
	);
}

////////////////////////////////////////
// CHTTPRequest
////////////////////////////////////////

CHTTPRequest::~CHTTPRequest() {
	WinHttpCloseHandle(m_hRequest);
}

CHTTPRequest::CHTTPRequest(
	_In_ const CHTTPConnection& Connection,
	_In_ const std::wstring& Verb,
	_In_ const std::wstring& TargetResource,
	_In_ const DWORD dwFlags
) {
	assert(Connection.GetServer());

	m_hRequest = WinHttpOpenRequest(
		Connection.GetServer(),
		Verb.c_str(),
		TargetResource.c_str(),
		NULL,
		WINHTTP_NO_REFERER,
		WINHTTP_DEFAULT_ACCEPT_TYPES,
		dwFlags
	);

	if (!m_hRequest) {
		OutputDebugStringA(
			std::vformat(
				"Failed to create a request: {}\n",
				std::make_format_args(GetLastError())
			).c_str()
		);
	}
}

CHTTPRequest::CHTTPRequest(
	_In_ const CHTTPConnection& Connection,
	_In_ const std::wstring& Verb,
	_In_ const HTTPResource_t& TargetResource,
	_In_ const DWORD dwFlags
) {
	assert(Connection.GetServer());

	std::wstring ResourceString = TargetResource.ToString();

	m_hRequest = WinHttpOpenRequest(
		Connection.GetServer(),
		Verb.c_str(),
		ResourceString.c_str(),
		NULL,
		WINHTTP_NO_REFERER,
		WINHTTP_DEFAULT_ACCEPT_TYPES,
		dwFlags
	);

	if (!m_hRequest) {
		OutputDebugStringA(
			std::vformat(
				"Failed to create a request: {}\n",
				std::make_format_args(GetLastError())
			).c_str()
		);
	}
}

std::string CHTTPRequest::ReadDataAvailable() {
	std::string ReturnValue;
	char* pMemoryBlock = nullptr;
	DWORD MemoryBlockSize = 0, AvailableDataSize, NumBytesRead;

	while (WinHttpQueryDataAvailable(GetRequestHandle(), &AvailableDataSize), AvailableDataSize) {
		if (AvailableDataSize > MemoryBlockSize) {
			free(pMemoryBlock);
			pMemoryBlock = reinterpret_cast<char*>(std::malloc(AvailableDataSize));
			MemoryBlockSize = AvailableDataSize;
			if (!pMemoryBlock)
				throw std::runtime_error("failed to allocate memory block");
		}

		if (!WinHttpReadData(GetRequestHandle(), pMemoryBlock, AvailableDataSize, &NumBytesRead)) {
			OutputDebugStringA(
				std::vformat(
					"Failed reading http data: {}\n",
					std::make_format_args(GetLastError())
				).c_str()
			);
		}

		ReturnValue.insert(ReturnValue.end(), pMemoryBlock, pMemoryBlock + NumBytesRead);
	}

	free(pMemoryBlock);
	return ReturnValue;
}

bool CHTTPRequest::RecieveResponse() {
	return WinHttpReceiveResponse(GetRequestHandle(), NULL);
}

bool CHTTPRequest::SendRequest(
	_In_reads_bytes_opt_(AdditionalHeadersSize) const wchar_t* pAdditionalHeaders,
	_In_opt_ const DWORD AdditionalHeadersSize,
	_In_reads_bytes_opt_(OptionalDataSize) void* pOptionalData,
	_In_opt_ const DWORD OptionalDataSize,
	_In_opt_ const DWORD AdditionalDataSizeAfterRequestSent
) {
	DWORD TotalLength = AdditionalDataSizeAfterRequestSent + OptionalDataSize;

	return WinHttpSendRequest(
		GetRequestHandle(),
		pAdditionalHeaders,
		AdditionalHeadersSize,
		pOptionalData,
		OptionalDataSize,
		TotalLength,
		0
	);
}

DWORD CHTTPRequest::WriteData(
	_In_reads_bytes_(DataSize) const void* pData,
	_In_ const DWORD DataSize
) {
	assert(DataSize <= std::numeric_limits<DWORD>::max());
	DWORD BytesWritten = 0;
	bool bSuccess;

	bSuccess = WinHttpWriteData(
		GetRequestHandle(),
		pData,
		DataSize,
		&BytesWritten
	);

	return BytesWritten;
}

DWORD CHTTPRequest::GetStatusCode() const {
	DWORD StatusCode;
	DWORD BufferLength = sizeof(StatusCode);

	WinHttpQueryHeaders(
		m_hRequest,
		WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, // Receives all the headers returned by the server. Each header is terminated by "\0". An additional "\0" terminates the list of headers.
		WINHTTP_HEADER_NAME_BY_INDEX,
		&StatusCode,
		&BufferLength,
		WINHTTP_NO_HEADER_INDEX
	);

	return StatusCode;
}

// returns true if added successfully
bool CHTTPRequest::AddHeader(const std::wstring& Header, DWORD dwModifiers) {
	assert(m_hRequest);

	assert(Header.size() <= std::numeric_limits<DWORD>::max());

	bool bRetVal = WinHttpAddRequestHeaders(
		m_hRequest,
		Header.c_str(),
		static_cast<DWORD>(Header.size()),
		dwModifiers
	);

	if (!bRetVal) {
		OutputDebugStringA(
			std::vformat(
				"Failed to add header: {}\n",
				std::make_format_args(GetLastError())
			).c_str()
		);
	}

	return bRetVal;
}

HINTERNET CHTTPRequest::GetRequestHandle() const {
	return m_hRequest;
}

////////////////////////////////////////
// CFile
////////////////////////////////////////

class CFile
{
public:
	using FileBufferType = std::pair<std::unique_ptr<char[]>, std::size_t>;

	CFile();
	CFile(const std::string& FilePath);
	CFile(const std::wstring& FilePath);

	FileBufferType ReadToBuffer();
	std::string ReadToString();
	std::wstring ReadToStringW();

	inline const std::size_t GetFileSize() const;
protected:
	std::ifstream m_File;
	std::size_t m_FileSize;
};

CFile::CFile() : m_File() {
	m_FileSize = 0;
}

CFile::CFile(const std::string& FilePath) :
	m_File(FilePath, std::ios_base::binary)
{
	if (m_File.is_open()) {
		// Seek to the end
		m_File.seekg(0, std::ios_base::end);

		// get our position and since we're at the end the file size
		m_FileSize = m_File.tellg();

		m_File.seekg(0, std::ios_base::beg);
	}
	else {
		m_FileSize = 0;
	}
}

CFile::CFile(const std::wstring& FilePath) :
	m_File(FilePath, std::ios_base::binary)
{
	if (m_File.is_open()) {
		// Seek to the end
		m_File.seekg(0, std::ios_base::end);

		// get our position and since we're at the end the file size
		m_FileSize = m_File.tellg();

		m_File.seekg(0, std::ios_base::beg);
	}
	else {
		m_FileSize = 0;
	}
}

CFile::FileBufferType CFile::ReadToBuffer() {
	if (!m_File.is_open())
		return std::make_pair(nullptr, 0);

	std::size_t BufferSize = GetFileSize();

	char* pFileBuffer = new char[BufferSize];
	std::memset(pFileBuffer, 0, BufferSize);
	m_File.seekg(0, std::ios_base::beg);
	m_File.read(pFileBuffer, GetFileSize());

	return std::make_pair(std::unique_ptr<char[]>(pFileBuffer), BufferSize);
}

std::string CFile::ReadToString() {
	FileBufferType Buffer = ReadToBuffer();

	return std::string(Buffer.first.get(), Buffer.second);
}

std::wstring CFile::ReadToStringW() {
	FileBufferType Buffer = ReadToBuffer();

	return ConvertString<std::string, std::wstring>(
		std::string(
			Buffer.first.get(),
			Buffer.first.get() + Buffer.second
		)
	);
}

inline const std::size_t CFile::GetFileSize() const { return m_FileSize; }

////////////////////////////////////////
// Json helpers
////////////////////////////////////////

typedef rapidjson::GenericDocument<rapidjson::UTF8<>> JSonDocument;

inline UUID_t FindAndGetUUID(
	_In_ JSonDocument::GenericValue::Object Object,
	_In_ const std::string& UUIDName,
	_In_ UUID_t FailValue = UUID_t::InvalidID()
) {
	const char* pszIntName = UUIDName.c_str();

	if (Object.HasMember(pszIntName)) {
		auto& Value = Object[pszIntName];

		if (Value.IsString())
			return UUID_t(Value.GetString());
	}

	return FailValue;
}

inline int FindAndGetInt(
	_In_ JSonDocument::GenericValue::Object Object,
	_In_ const std::string& IntName,
	_In_ int FailValue = 0
) {
	const char* pszIntName = IntName.c_str();

	if (Object.HasMember(pszIntName)) {
		auto& Value = Object[pszIntName];

		if (Value.IsInt())
			return Value.GetInt();
	}

	return FailValue;
}

inline unsigned int FindAndGetUInt(
	_In_ JSonDocument::GenericValue::Object Object,
	_In_ const std::string& UIntName,
	_In_ unsigned int FailValue = 0
) {
	const char* pszUIntName = UIntName.c_str();

	if (Object.HasMember(pszUIntName)) {
		auto& Value = Object[pszUIntName];

		if (Value.IsUint())
			return Value.GetUint();
	}

	return FailValue;
}

inline std::int64_t FindAndGetInt64(
	_In_ JSonDocument::GenericValue::Object Object,
	_In_ const std::string& Int64Name,
	_In_ std::int64_t FailValue = 0
) {
	const char* pszInt64Name = Int64Name.c_str();

	if (Object.HasMember(pszInt64Name)) {
		auto& Value = Object[pszInt64Name];

		if (Value.IsInt64())
			return Value.GetInt64();
	}

	return FailValue;
}

inline std::uint64_t FindAndGetUInt64(
	_In_ JSonDocument::GenericValue::Object Object,
	_In_ const std::string& UInt64Name,
	_In_ std::uint64_t FailValue = 0
) {
	const char* pszUInt64Name = UInt64Name.c_str();

	if (Object.HasMember(pszUInt64Name)) {
		auto& Value = Object[pszUInt64Name];

		if (Value.IsUint64())
			return Value.GetUint64();
	}

	return FailValue;
}

inline float FindAndGetFloat(
	_In_ JSonDocument::GenericValue::Object Object,
	_In_ const std::string& FloatName,
	_In_ float FailValue = 0.f
) {
	const char* pszFloatName = FloatName.c_str();

	if (Object.HasMember(pszFloatName)) {
		auto& Value = Object[pszFloatName];

		if (Value.IsFloat())
			return Value.GetFloat();
	}

	return FailValue;
}

inline double FindAndGetDouble(
	_In_ JSonDocument::GenericValue::Object Object,
	_In_ const std::string& FloatName,
	_In_ double FailValue = 0.0
) {
	const char* pszFloatName = FloatName.c_str();

	if (Object.HasMember(pszFloatName)) {
		auto& Value = Object[pszFloatName];

		if (Value.IsDouble())
			return Value.GetDouble();
	}

	return FailValue;
}

inline bool FindAndGetBool(
	_In_ JSonDocument::GenericValue::Object Object,
	_In_ const std::string& BoolName,
	_In_ bool FailValue = false
) {
	const char* pszBoolName = BoolName.c_str();

	if (Object.HasMember(pszBoolName)) {
		auto& Value = Object[pszBoolName];
		if (Value.IsBool())
			return Value.GetBool();
	}

	return FailValue;
}

inline std::string FindAndGetString(
	_In_ JSonDocument::GenericValue::Object Object,
	_In_ const std::string& StringName,
	_In_ std::string FailValue = ""
) {
	const char* pszStringName = StringName.c_str();

	if (Object.HasMember(pszStringName)) {
		auto& Value = Object[pszStringName];
		if (Value.IsString())
			return Value.GetString();
	}
	return FailValue;
}

template<typename T>
inline std::vector<T> FindAndGetArray(
	_In_ JSonDocument::GenericValue::Object Object,
	_In_ const std::string& ArrayName
) {
	std::vector<T> Vec;
	const char* pszArrayName = ArrayName.c_str();

	if (Object.HasMember(pszArrayName)) {
		auto& Array = Object[pszArrayName];

		if (Array.IsArray()) {
			for (auto Element = Array.Begin(); Element != Array.End(); Element++) {
				if (Element->IsObject())
					Vec.emplace_back(Element->GetObject());
			}
		}
	}

	return Vec;
}


// Got lazy.  Took it from here:
//		https://gist.github.com/darelf/0f96e1d313e1d0da5051e1a6eff8d329

const char base64_url_alphabet[] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
	'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
	'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'
};

template<typename T>
std::basic_string<T, std::char_traits<T>, std::allocator<T>> base64_encode(
	const std::basic_string<T, std::char_traits<T>, std::allocator<T>>& in
) {
	std::basic_string<T, std::char_traits<T>, std::allocator<T>> out;
	int val = 0, valb = -6;
	size_t len = in.length();
	unsigned int i = 0;
	for (i = 0; i < len; i++) {
		unsigned char c = static_cast<unsigned char>(in[i]);
		val = (val << 8) + c;
		valb += 8;
		while (valb >= 0) {
			out.push_back(base64_url_alphabet[(val >> valb) & 0x3F]);
			valb -= 6;
		}
	}
	if (valb > -6) {
		out.push_back(base64_url_alphabet[((val << 8) >> (valb + 8)) & 0x3F]);
	}
	return out;
}

template<typename T>
std::basic_string<T, std::char_traits<T>, std::allocator<T>> base64_decode(
	const std::basic_string<T, std::char_traits<T>, std::allocator<T>>& in
) {
	std::basic_string<T, std::char_traits<T>, std::allocator<T>> out;
	std::vector<int> T(256, -1);
	unsigned int i;
	for (i = 0; i < 64; i++) T[base64_url_alphabet[i]] = i;

	int val = 0, valb = -8;
	for (i = 0; i < in.length(); i++) {
		unsigned char c = in[i];
		if (T[c] == -1) break;
		val = (val << 6) + T[c];
		valb += 6;
		if (valb >= 0) {
			out.push_back(char((val >> valb) & 0xFF));
			valb -= 8;
		}
	}
	return out;
}

inline TeamID_t GetTeamIDFromString(const std::string& TeamIDStr) {
	if (TeamIDStr == "Red")
		return TeamID_t::Attacker;

	if (TeamIDStr == "Blue")
		return TeamID_t::Defender;

	return TeamID_t::None;
}

static inline std::string ValorantQueueTypeToString(const ValorantQueueType_t QueueType) {
	switch (QueueType)
	{
	case ValorantQueueType_t::Unrated:
		return "unrated";
	case ValorantQueueType_t::Competitive:
		return "competitive";
	case ValorantQueueType_t::Swiftplay:
		return "swiftplay";
	case ValorantQueueType_t::SpikeRush:
		return "spikerush";
	case ValorantQueueType_t::Deathmatch:
		return "deathmatch";
	case ValorantQueueType_t::TeamDeathmatch:
		return "hurm"; // ?
	case ValorantQueueType_t::Premier:
		return "premier";
	default:
		throw std::invalid_argument("Invalid queue type");
	}
}

static inline std::wstring ValorantQueueTypeToStringW(const ValorantQueueType_t QueueType) {
	switch (QueueType)
	{
	case ValorantQueueType_t::Unrated:
		return L"unrated";
	case ValorantQueueType_t::Competitive:
		return L"competitive";
	case ValorantQueueType_t::Swiftplay:
		return L"swiftplay";
	case ValorantQueueType_t::SpikeRush:
		return L"spikerush";
	case ValorantQueueType_t::Deathmatch:
		return L"deathmatch";
	case ValorantQueueType_t::TeamDeathmatch:
		return L"hurm"; // ?
	case ValorantQueueType_t::Premier:
		return L"premier";
	default:
		throw std::invalid_argument("Invalid queue type");
	}
}

static inline ValorantQueueType_t StringtoValorantQueueType(const std::string& QueueString) {
	static std::map<std::string, ValorantQueueType_t> Map = {
		{ "unrated", ValorantQueueType_t::Unrated },
		{ "competitive", ValorantQueueType_t::Competitive },
		{ "swiftplay", ValorantQueueType_t::Swiftplay },
		{ "spikerush", ValorantQueueType_t::SpikeRush },
		{ "deathmatch", ValorantQueueType_t::Deathmatch },
		{ "hurm", ValorantQueueType_t::TeamDeathmatch },
		{ "premier", ValorantQueueType_t::Premier }
	};

	auto It = Map.find(QueueString);

	if (It == Map.cend())
		return ValorantQueueType_t::Unknown;

	return It->second;
}

inline Color32_t HexStringToColor(const std::string& ColorString) {
	std::uint32_t Color32 = std::stoul(ColorString, 0, 16);

	return Color32_t(
		(Color32 >> 24) & 0xFF,
		(Color32 >> 16) & 0xFF,
		(Color32 >> 8) & 0xFF,
		Color32 & 0xFF
	);
}

///////////////////////////////////////////////////
// Official API Structures
///////////////////////////////////////////////////
typedef std::string MapURL;
typedef std::uint8_t TierID;

///////////////////////////////////////////////////
// UUID_t
///////////////////////////////////////////////////
UUID_t::UUID_t() : m_ID(szInvalidID), m_IDW(szInvalidIDW) {}

UUID_t::UUID_t(const std::string_view& ID) {
	// gross but who cares
	if (ID.length() != szInvalidID.length()) {
		m_ID = szInvalidID;
		return;
	}

	m_ID = ID;
	std::transform(
		m_ID.cbegin(),
		m_ID.cend(),
		m_ID.begin(),
		[](const char C) -> char {
			return static_cast<char>(std::tolower(C));
		}
	);

	m_IDW = ConvertString<std::string, std::wstring>(m_ID);
}

///////////////////////////////////////////////////
// ValorantRank_t
///////////////////////////////////////////////////

ValorantRank_t::ValorantRank_t() {
	m_Rank = Rank_t::Unknown;
	m_RankColor = Color32_t(255, 255, 255, 255);
	m_Division = DivisionNone;
	m_TierName = "Unknown";
	m_FullName = "Unknown";
}

ValorantRank_t::ValorantRank_t(
	Rank_t Rank,
	std::string TierName,
	std::uint8_t Division,
	Color32_t RankColor
) {
	m_Rank = Rank;
	m_RankColor = RankColor;
	m_Division = Division;
	m_TierName = TierName;
	m_FullName = TierName;

	if (Division != ValorantRank_t::DivisionNone)
		m_FullName += " " + std::to_string(Division);
}

namespace RiotAPIStructure {
	struct RiotEntitlements_t {
		RiotEntitlements_t() {}
		RiotEntitlements_t(_In_ JSonDocument::GenericValue::Object Object) :
			m_Subject(FindAndGetUUID(Object, "subject")),
			m_AccessToken(ConvertString<std::string, std::wstring>(FindAndGetString(Object, "accessToken"))),
			m_Token(ConvertString<std::string, std::wstring>(FindAndGetString(Object, "token"))) {}

		inline const UUID_t& GetSubject() const { return m_Subject; }
		inline const UUID_t& GetPUUID() const { return m_Subject; }

		// used in headers:
		//		Authorization: Bearier AccessToken
		inline const std::wstring& GetAccessToken() const { return m_AccessToken; }

		// used in headers:
		//		X-Riot-Entitlements-JWT: (Token)
		inline const std::wstring& GetToken() const { return m_Token; }
	protected:
		UUID_t m_Subject; // subject - puuid
		std::wstring m_AccessToken; // accessToken
		std::wstring m_Token; // token
	};

	struct Session_t {
		struct LaunchConfiguration_t {
			LaunchConfiguration_t() {}
			LaunchConfiguration_t(
				_In_ JSonDocument::GenericValue::Object Object
			) {
				if (Object.HasMember("arguments")) {
					auto Array = Object["arguments"].GetArray();

					for (auto& ArrayValueObject : Array) {
						m_Arguments.emplace_back(ArrayValueObject.GetString());
					}
				}

				m_Executable = FindAndGetString(Object, "executable");
				m_Locale = FindAndGetString(Object, "locale");
				m_WorkingDirectory = FindAndGetString(Object, "workingDirectory");
			}

			inline const std::vector<std::string>& GetLaunchArguments() const { return m_Arguments; }
			inline const std::string& GetExecutable() const { return m_Executable; }
			inline const std::string& GetLocale() const { return m_Locale; }
			inline const std::string& GetWorkingDirectory() const { return m_WorkingDirectory; }
		protected:
			std::vector<std::string> m_Arguments;
			std::string m_Executable;
			std::string m_Locale;
			std::string m_WorkingDirectory;
		};
		Session_t() {}
		Session_t(
			_In_ JSonDocument::GenericValue::Object Object
		) {
			if (Object.HasMember("launchConfiguration") && Object["launchConfiguration"].IsObject())
				m_LaunchConfig = LaunchConfiguration_t(Object["launchConfiguration"].GetObject());

			m_PatchlineFullName = FindAndGetString(Object, "patchlineFullName");
			m_PatchlineID = FindAndGetString(Object, "patchlineId");
			m_Phase = FindAndGetString(Object, "phase");
			m_ProductId = FindAndGetString(Object, "productId");
			m_Version = FindAndGetString(Object, "version");
		}

		inline const LaunchConfiguration_t& GetLaunchConfig() const { return m_LaunchConfig; }
		inline const std::string& GetPatchlineFullName() const { return m_PatchlineFullName; }
		inline const std::string& GetPatchlineID() const { return m_PatchlineID; }
		inline const std::string& GetPhase() const { return m_Phase; }
		inline const std::string& GetProductID() const { return m_ProductId; }
		inline const std::string& GetVersion() const { return m_Version; }
	protected:
		LaunchConfiguration_t m_LaunchConfig;
		std::string m_PatchlineFullName;
		std::string m_PatchlineID;
		std::string m_Phase;
		std::string m_ProductId;
		std::string m_Version;
	};

	struct PreGamePlayer_t {
		PreGamePlayer_t() : m_Version(0) {}

		PreGamePlayer_t(
			_In_ JSonDocument::GenericValue::Object Object
		) {
			m_Subject = FindAndGetUUID(Object, "Subject");
			m_MatchID = FindAndGetUUID(Object, "MatchID");
			m_Version = FindAndGetUInt64(Object, "Version");
		}

		// UUID
		UUID_t m_Subject;
		UUID_t m_MatchID;
		std::uint64_t m_Version;
	};

	struct Identity_t {
		Identity_t() {
			AccountLevel = 0;
			Incognito = false;
			HideAccountLevel = false;
		}

		Identity_t(
			_In_ JSonDocument::GenericValue::Object Object
		) {
			Subject = FindAndGetUUID(Object, "Subject");
			PlayerCardID = FindAndGetString(Object, "PlayerCardID");
			PlayerTitleID = FindAndGetString(Object, "PlayerTitleID");
			AccountLevel = FindAndGetUInt64(Object, "AccountLevel");
			PreferredLevelBorderID = FindAndGetString(Object, "PreferredLevelBorderID");

			Incognito = FindAndGetBool(Object, "Incognito");
			HideAccountLevel = FindAndGetBool(Object, "HideAccountLevel");
		}

		// PUUID
		UUID_t Subject;
		std::string PlayerCardID;
		std::string PlayerTitleID;
		std::uint64_t AccountLevel;
		std::string PreferredLevelBorderID;
		bool Incognito; // Streamer mode?
		bool HideAccountLevel;
	};

	struct SeasonalBadgeInfo_t {
		SeasonalBadgeInfo_t() {
			NumberOfWins = 0;
			Rank = 0;
			LeaderboardRank = 0;
		}

		SeasonalBadgeInfo_t(
			_In_ JSonDocument::GenericValue::Object Object
		) {
			SeasonID = FindAndGetUUID(Object, "SeasonID");
			NumberOfWins = FindAndGetUInt(Object, "NumberOfWins");
			Rank = FindAndGetUInt(Object, "Rank");
			LeaderboardRank = FindAndGetUInt(Object, "LeaderboardRank");
		}

		UUID_t SeasonID;
		std::uint64_t NumberOfWins;
		std::uint64_t Rank;
		std::uint64_t LeaderboardRank;
	};

	struct PreGameMatch_t {
		struct Player_t {
			Player_t(
				_In_ JSonDocument::GenericValue::Object Object
			) {
				m_Subject = FindAndGetUUID(Object, "Subject");
				m_CharacterID = FindAndGetUUID(Object, "CharacterID");
				m_CharacterSelectionState = FindAndGetString(Object, "CharacterSelectionState");
				m_PregamePlayerState = FindAndGetString(Object, "PregamePlayerState");
				m_CompetitiveTier = static_cast<TierID>(FindAndGetUInt64(Object, "CompetitiveTier"));
				m_bIsCaptain = FindAndGetBool(Object, "IsCaptain");

				if (Object.HasMember("PlayerIdentity")) {
					auto& PlayerIdentity = Object["PlayerIdentity"];
					if (PlayerIdentity.IsObject())
						m_Identity = Identity_t(PlayerIdentity.GetObject());
				}

				if (Object.HasMember("SeasonalBadgeInfo")) {
					auto& SeasonalBadgeInfo = Object["SeasonalBadgeInfo"];
					if (SeasonalBadgeInfo.IsObject())
						m_SeasonalBadgeInfo = SeasonalBadgeInfo_t(SeasonalBadgeInfo.GetObject());
				}
			}

			Identity_t m_Identity;
			SeasonalBadgeInfo_t m_SeasonalBadgeInfo;

			// PUUID
			UUID_t m_Subject;

			// Agent UUID
			UUID_t m_CharacterID;

			std::string m_CharacterSelectionState;
			std::string m_PregamePlayerState;
			TierID m_CompetitiveTier;
			bool m_bIsCaptain;
		};

		struct Team_t {
			Team_t() : m_TeamID(TeamID_t::None) {}
			Team_t(
				_In_ JSonDocument::GenericValue::Object Object
			) {
				m_TeamID = GetTeamIDFromString(FindAndGetString(Object, "TeamID"));
				if (Object.HasMember("Players")) {
					auto& Players = Object["Players"];
					if (Players.IsArray()) {
						auto PlayersArray = Players.GetArray();

						for (auto& PlayerObject : PlayersArray) {
							m_Players.emplace_back(PlayerObject.GetObject());
						}
					}
				}
			}

			TeamID_t m_TeamID;
			std::vector<Player_t> m_Players;
		};

		PreGameMatch_t() : m_Version(0), m_IsRanked(false) {}
		PreGameMatch_t(
			_In_ JSonDocument::GenericValue::Object Object
		) {
			m_MatchID = FindAndGetUUID(Object, "ID");
			m_Version = FindAndGetUInt64(Object, "Version");

			if (Object.HasMember("Teams")) {
				auto& Teams = Object["Teams"];
				if (Teams.IsArray()) {
					auto TeamsArray = Teams.GetArray();

					for (auto& TeamObject : TeamsArray) {
						m_Teams.emplace_back(TeamObject.GetObject());
					}
				}
			}

			if (Object.HasMember("AllyTeam")) {
				auto& AllyTeam = Object["AllyTeam"];
				if (AllyTeam.IsObject())
					m_AllyTeam = Team_t(AllyTeam.GetObject());
			}

			if (Object.HasMember("EnemyTeam")) {
				auto& EnemyTeam = Object["EnemyTeam"];
				if (EnemyTeam.IsObject())
					m_EnemyTeam = Team_t(EnemyTeam.GetObject());
			}

			m_Mode = FindAndGetString(Object, "Mode");
			m_QueueID = FindAndGetString(Object, "QueueID");
			m_IsRanked = FindAndGetBool(Object, "IsRanked");
			m_MapID = FindAndGetString(Object, "MapID");
		}

		// Match ID
		UUID_t m_MatchID;
		std::uint64_t m_Version;
		std::vector<Team_t> m_Teams;
		Team_t m_AllyTeam;
		Team_t m_EnemyTeam;
		std::string m_Mode;
		std::string m_QueueID;
		MapURL m_MapID;
		bool m_IsRanked;
	};

	struct AccountXP_t {
		struct Progress_t {
			Progress_t() : Level(0), XP(0) {}
			Progress_t(
				_In_ JSonDocument::GenericValue::Object Object
			) {
				Level = FindAndGetUInt64(Object, "Level");
				XP = FindAndGetUInt64(Object, "XP");
			}

			std::uint64_t Level;
			std::uint64_t XP;
		};

		struct History_t {
			History_t() : XPDelta(0) {}

			History_t(
				_In_ JSonDocument::GenericValue::Object Object
			) {
				ID = FindAndGetUUID(Object, "ID");
				MatchStart = FindAndGetString(Object, "MatchStart");

				if (Object.HasMember("StartProgress") && Object["StartProgress"].IsObject()) {
					StartProgress = Progress_t(Object["StartProgress"].GetObject());
				}

				if (Object.HasMember("EndProgress") && Object["EndProgress"].IsObject()) {
					EndProgress = Progress_t(Object["EndProgress"].GetObject());
				}

				XPDelta = FindAndGetUInt64(Object, "XPDelta");
			}

			// match ID
			UUID_t ID;
			std::string MatchStart;
			Progress_t StartProgress;
			Progress_t EndProgress;
			std::uint64_t XPDelta;
		};

		AccountXP_t() : Version(0) {}
		AccountXP_t(
			_In_ JSonDocument::GenericValue::Object Object
		) {
			Version = FindAndGetUInt64(Object, "Version");
			Subject = FindAndGetUUID(Object, "Subject");

			if (Object.HasMember("Progress") && Object["Progress"].IsObject()) {
				Progress = Progress_t(Object["Progress"].GetObject());
			}

			if (Object.HasMember("History") && Object["History"].IsArray()) {
				auto HistoryArray = Object["History"].GetArray();

				for (auto& HistoryValue : HistoryArray) {
					History.emplace_back(HistoryValue.GetObject());
				}
			}

			LastTimeGrantedFirstWin = FindAndGetString(Object, "LastTimeGrantedFirstWin");
			NextTimeFirstWinAvailable = FindAndGetString(Object, "NextTimeFirstWinAvailable");
		}


		std::uint64_t Version;

		// PUUID
		UUID_t Subject;
		Progress_t Progress;
		std::vector<History_t> History;
		std::string LastTimeGrantedFirstWin;
		std::string NextTimeFirstWinAvailable;
	};


	struct PlayerLoadout_t {
		struct Gun_t {
			Gun_t() {}
			Gun_t(
				_In_ JSonDocument::GenericValue::Object Object
			) {
				ID = FindAndGetUUID(Object, "ID");
				CharmInstanceID = FindAndGetUUID(Object, "CharmInstanceID");
				CharmID = FindAndGetUUID(Object, "CharmID");
				CharmLevelID = FindAndGetUUID(Object, "CharmLevelID");
				SkinID = FindAndGetUUID(Object, "SkinID");
				SkinLevelID = FindAndGetUUID(Object, "SkinLevelID");
				ChromaID = FindAndGetUUID(Object, "ChromaID");
			}

			UUID_t ID;
			UUID_t CharmInstanceID;
			UUID_t CharmID;
			UUID_t CharmLevelID;
			UUID_t SkinID;
			UUID_t SkinLevelID;
			UUID_t ChromaID;
		};

		struct Spray_t {
			Spray_t() {}
			Spray_t(
				_In_ JSonDocument::GenericValue::Object Object
			) {
				EquipSlotID = FindAndGetUUID(Object, "EquipSlotID");
				SprayID = FindAndGetUUID(Object, "SprayID");
			}

			UUID_t EquipSlotID;
			UUID_t SprayID;
		};

		struct Identity_t {
			Identity_t() : AccountLevel(0), HideAccountLevel(false) {}
			Identity_t(
				_In_ JSonDocument::GenericValue::Object Object
			) {
				PlayerCardID = FindAndGetUUID(Object, "PlayerCardID");
				PlayerTitleID = FindAndGetUUID(Object, "PlayerTitleID");
				AccountLevel = FindAndGetUInt64(Object, "AccountLevel");
				PreferredLevelBorderID = FindAndGetUUID(Object, "PreferredLevelBorderID");
				HideAccountLevel = FindAndGetBool(Object, "HideAccountLevel");
			}

			UUID_t PlayerCardID;
			UUID_t PlayerTitleID;
			std::uint64_t AccountLevel;
			UUID_t PreferredLevelBorderID;
			bool HideAccountLevel;
		};

		PlayerLoadout_t() : Version(0),
			Incognito(false) {}

		PlayerLoadout_t(
			_In_ JSonDocument::GenericValue::Object Object
		) {
			Subject = FindAndGetUUID(Object, "Subject");
			Version = FindAndGetUInt64(Object, "Version");

			if (Object.HasMember("Guns") && Object["Guns"].IsArray()) {
				auto GunsArray = Object["Guns"].GetArray();

				for (auto& Gun : GunsArray) {
					Guns.emplace_back(Gun.GetObject());
				}
			}

			if (Object.HasMember("Sprays") && Object["Sprays"].IsArray()) {
				auto SpraysArray = Object["Sprays"].GetArray();

				for (auto& Spray : SpraysArray) {
					Sprays.emplace_back(Spray.GetObject());
				}
			}

			if (Object.HasMember("Identity") && Object["Identity"].IsObject()) {
				Identity = Identity_t(Object["Identity"].GetObject());
			}

			Incognito = FindAndGetBool(Object, "Incognito");
		}

		// PUUID
		UUID_t Subject;
		std::uint64_t Version;
		std::vector<Gun_t> Guns;
		std::vector<Spray_t> Sprays;
		Identity_t Identity;
		bool Incognito;
	};

	struct CurrentGamePlayer_t {
		CurrentGamePlayer_t() : m_Version(0) {}

		CurrentGamePlayer_t(
			_In_ JSonDocument::GenericValue::Object Object
		) {
			m_Subject = FindAndGetUUID(Object, "Subject");
			m_MatchID = FindAndGetUUID(Object, "MatchID");
			m_Version = FindAndGetUInt64(Object, "Version");
		}

		// PUUID
		UUID_t m_Subject;
		UUID_t m_MatchID;
		std::uint64_t m_Version;
	};

	struct CurrentGameMatch_t {
		struct ConnectionDetails_t {
			ConnectionDetails_t() :
				m_GameServerPort(0),
				m_GameServerObfuscatedIP(0),
				m_GameClientHash(0) {}

			ConnectionDetails_t(
				_In_ JSonDocument::GenericValue::Object Object
			) {

				if (Object.HasMember("GameServerHosts") && Object["GameServerHosts"].IsArray()) {
					auto GameServerHostsArray = Object["GameServerHosts"].GetArray();

					for (auto& _GameServerHost : GameServerHostsArray) {
						if (_GameServerHost.IsString())
							m_GameServerHosts.emplace_back(_GameServerHost.GetString());
					}
				}

				m_GameServerHost = FindAndGetString(Object, "GameServerHost");
				m_GameServerPort = FindAndGetUInt64(Object, "GameServerPort");
				m_GameServerObfuscatedIP = FindAndGetUInt64(Object, "GameServerObfuscatedIP");
				m_GameClientHash = FindAndGetUInt64(Object, "GameClientHash");
				m_PlayerKey = FindAndGetString(Object, "PlayerKey");
			}


			std::vector<std::string> m_GameServerHosts;
			std::string m_GameServerHost;
			std::uint64_t m_GameServerPort;
			std::uint64_t m_GameServerObfuscatedIP;
			std::uint64_t m_GameClientHash;
			std::string m_PlayerKey;
		};

		struct Player_t {
			Player_t(
				_In_ JSonDocument::GenericValue::Object Object
			) {
				m_Subject = FindAndGetUUID(Object, "Object");
				m_TeamID = GetTeamIDFromString(FindAndGetString(Object, "TeamID"));
				m_CharacterID = FindAndGetUUID(Object, "CharacterID");

				if (Object.HasMember("PlayerIdentity") && Object["PlayerIdentity"].IsObject())
					m_Identity = Identity_t(Object["PlayerIdentity"].GetObject());

				if (Object.HasMember("SeasonalBadgeInfo") && Object["SeasonalBadgeInfo"].IsObject())
					m_SeasonalBadgeInfo = SeasonalBadgeInfo_t(Object["SeasonalBadgeInfo"].GetObject());

				m_IsCoach = FindAndGetBool(Object, "IsCoach");
				m_IsAssociated = FindAndGetBool(Object, "IsAssociated");
			}

			// PUUID
			UUID_t m_Subject;
			TeamID_t m_TeamID;
			UUID_t m_CharacterID;
			Identity_t m_Identity;
			SeasonalBadgeInfo_t m_SeasonalBadgeInfo;
			bool m_IsCoach;
			bool m_IsAssociated;
		};

		CurrentGameMatch_t() : m_Version(0), m_IsReconnectable(false) {}
		CurrentGameMatch_t(
			_In_ JSonDocument::GenericValue::Object Object
		) {
			m_MatchID = FindAndGetUUID(Object, "MatchID");
			m_Version = FindAndGetUInt64(Object, "Version");
			m_MapID = FindAndGetString(Object, "MapID");
			m_ModeID = FindAndGetString(Object, "ModeID");
			m_GamePodID = FindAndGetString(Object, "GamePodID");
			m_AllMUCName = FindAndGetString(Object, "AllMUCName");
			m_TeamMUCName = FindAndGetString(Object, "TeamMUCName");
			m_IsReconnectable = FindAndGetBool(Object, "IsReconnectable");

			if (Object.HasMember("ConnectionDetails") && Object["ConnectionDetails"].IsObject()) {
				m_ConnectionDetails = ConnectionDetails_t(Object["ConnectionDetails"].GetObject());
			}

			if (Object.HasMember("Players") && Object["Players"].IsArray()) {
				auto PlayersArray = Object["Players"].GetArray();

				for (auto& Player : PlayersArray) {
					m_Players.emplace_back(Player.GetObject());
				}
			}
		}

		UUID_t m_MatchID;
		std::uint64_t m_Version;
		std::string m_MapID;
		std::string m_ModeID;
		std::string m_GamePodID;

		std::string m_AllMUCName;
		std::string m_TeamMUCName;
		bool m_IsReconnectable;

		ConnectionDetails_t m_ConnectionDetails;

		std::vector<Player_t> m_Players;
	};


	struct PlayerMMR_t {
		struct LatestCompetitiveUpdate_t {
			LatestCompetitiveUpdate_t() : TierAfterUpdate(0),
				TierBeforeUpdate(0),
				RankedRatingAfterUpdate(0),
				RankedRatingBeforeUpdate(0),
				RankedRatingEarned(0),
				RankedRatingPerformanceBonus(0),
				AFKPenalty(0) {}
			LatestCompetitiveUpdate_t(
				_In_ JSonDocument::GenericValue::Object Object
			) {
				MatchID = FindAndGetString(Object, "MatchID");
				MapID = FindAndGetString(Object, "MapID");
				SeasonID = FindAndGetUUID(Object, "SeasonID");
				MatchStartTime = CTime(FindAndGetUInt64(Object, "MatchStartTime"));
				TierAfterUpdate = static_cast<TierID>(FindAndGetUInt64(Object, "TierAfterUpdate"));
				TierBeforeUpdate = static_cast<TierID>(FindAndGetUInt64(Object, "TierBeforeUpdate"));
				RankedRatingAfterUpdate = FindAndGetUInt64(Object, "RankedRatingAfterUpdate");
				RankedRatingBeforeUpdate = FindAndGetUInt64(Object, "RankedRatingBeforeUpdate");
				RankedRatingEarned = FindAndGetUInt64(Object, "RankedRatingEarned");
				RankedRatingPerformanceBonus = FindAndGetUInt64(Object, "RankedRatingPerformanceBonus");
				AFKPenalty = FindAndGetUInt64(Object, "AFKPenalty");
			}

			std::string MatchID;
			std::string MapID;
			UUID_t SeasonID;
			CTime MatchStartTime;
			TierID TierAfterUpdate;
			TierID TierBeforeUpdate;
			std::uint64_t RankedRatingAfterUpdate;
			std::uint64_t RankedRatingBeforeUpdate;
			std::uint64_t RankedRatingEarned;
			std::uint64_t RankedRatingPerformanceBonus;
			std::uint64_t AFKPenalty;
		};

		struct QueueSkills_t {
			struct SeasonalInfoBySeasonID_t {
				SeasonalInfoBySeasonID_t() : NumberOfWins(0),
					NumberOfWinsWithPlacements(0),
					NumberOfGames(0),
					Rank(0),
					CapstoneWins(0),
					LeaderboardRank(0),
					CompetitiveTier(0),
					RankedRating(0),
					GamesNeededForRating(0),
					TotalWinsNeededForRank(0) {}

				SeasonalInfoBySeasonID_t(
					_In_ JSonDocument::GenericValue::Object Object
				) {
					SeasonID = FindAndGetUUID(Object, "SeasonID");
					NumberOfWins = FindAndGetUInt64(Object, "NumberOfWins");
					NumberOfWinsWithPlacements = FindAndGetUInt64(Object, "NumberOfWinsWithPlacements");
					NumberOfGames = FindAndGetUInt64(Object, "NumberOfGames");
					Rank = FindAndGetUInt64(Object, "Rank");
					CapstoneWins = FindAndGetUInt64(Object, "CapstoneWins");
					LeaderboardRank = FindAndGetUInt64(Object, "LeaderboardRank");
					CompetitiveTier = static_cast<TierID>(FindAndGetUInt64(Object, "CompetitiveTier"));
					RankedRating = FindAndGetUInt64(Object, "RankedRating");

					if (Object.HasMember("WinsByTier") && Object["WinsByTier"].IsObject()) {
						auto WinsByTierObject = Object["WinsByTier"].GetObject();

						for (auto& WinObject : WinsByTierObject) {
							if (WinObject.name.IsString() && WinObject.value.IsNumber()) {
								TierID Tier = static_cast<TierID>(std::stoul(WinObject.name.GetString()));

								WinsByTier.emplace(Tier, WinObject.value.GetUint64());
							}
						}
					}

					GamesNeededForRating = FindAndGetUInt64(Object, "GamesNeededForRating");
					TotalWinsNeededForRank = FindAndGetUInt64(Object, "TotalWinsNeededForRank");
				}

				UUID_t SeasonID;
				std::uint64_t NumberOfWins;
				std::uint64_t NumberOfWinsWithPlacements;
				std::uint64_t NumberOfGames;
				std::uint64_t Rank;
				std::uint64_t CapstoneWins;
				std::uint64_t LeaderboardRank;
				TierID CompetitiveTier;
				std::uint64_t RankedRating;
				std::map<TierID, std::uint64_t> WinsByTier;
				std::uint64_t GamesNeededForRating;
				std::uint64_t TotalWinsNeededForRank;
			};

			QueueSkills_t() : TotalGamesNeededForRating(0),
				TotalGamesNeededForLeaderboard(0),
				CurrentSeasonGamesNeededForRating(0) { }
			QueueSkills_t(
				_In_ JSonDocument::GenericValue::Object Object
			) {
				TotalGamesNeededForRating = FindAndGetUInt64(Object, "TotalGamesNeededForRating");
				TotalGamesNeededForLeaderboard = FindAndGetUInt64(Object, "TotalGamesNeededForLeaderboard");
				CurrentSeasonGamesNeededForRating = FindAndGetUInt64(Object, "CurrentSeasonGamesNeededForRating");

				if (Object.HasMember("SeasonalInfoBySeasonID") && Object["SeasonalInfoBySeasonID"].IsObject()) {
					auto SeasonalInfoObject = Object["SeasonalInfoBySeasonID"].GetObject();

					for (auto& Season : SeasonalInfoObject) {
						if (Season.name.IsString() && Season.value.IsObject()) {
							SeasonalInfoBySeasonID.emplace(
								Season.name.GetString(),
								Season.value.GetObject()
							);
						}
					}
				}
			}

			std::uint64_t TotalGamesNeededForRating;
			std::uint64_t TotalGamesNeededForLeaderboard;
			std::uint64_t CurrentSeasonGamesNeededForRating;
			std::map<UUID_t, SeasonalInfoBySeasonID_t> SeasonalInfoBySeasonID;
		};

		PlayerMMR_t() : Version(0),
			NewPlayerExperienceFinished(false),
			IsLoaderboardAnonymized(false),
			IsActRankBadgeHidden(false) {}
		PlayerMMR_t(
			_In_ JSonDocument::GenericValue::Object Object
		) {
			Version = FindAndGetUInt64(Object, "Version");
			Subject = FindAndGetUUID(Object, "Subject");


			if (Object.HasMember("QueueSkills") && Object["QueueSkills"].IsObject()) {
				auto QueueSkillsObject = Object["QueueSkills"].GetObject();

				for (auto& QueueKeyValue : QueueSkillsObject) {
					if (!QueueKeyValue.name.IsString() || !QueueKeyValue.value.IsObject())
						continue;

					ValorantQueueType_t QueueType = StringtoValorantQueueType(QueueKeyValue.name.GetString());

					if (QueueType == ValorantQueueType_t::Unknown)
						continue;

					QueueSkills.emplace(
						QueueType,
						QueueKeyValue.value.GetObject()
					);
				}
			}

			if (Object.HasMember("LatestCompetitiveUpdate") && Object["LatestCompetitiveUpdate"].IsObject())
				LatestCompetitiveUpdate = LatestCompetitiveUpdate_t(Object["LatestCompetitiveUpdate"].GetObject());

			NewPlayerExperienceFinished = FindAndGetBool(Object, "NewPlayerExperienceFinished");
			IsLoaderboardAnonymized = FindAndGetBool(Object, "IsLoaderboardAnonymized");
			IsActRankBadgeHidden = FindAndGetBool(Object, "IsActRankBadgeHidden");
		}

		std::uint64_t Version;

		// PUUID
		UUID_t Subject;

		// key is Queue Type
		std::map<ValorantQueueType_t, QueueSkills_t> QueueSkills;
		LatestCompetitiveUpdate_t LatestCompetitiveUpdate;
		bool NewPlayerExperienceFinished;
		bool IsLoaderboardAnonymized;
		bool IsActRankBadgeHidden;
	};

	struct NameServiceResponse_t {
		NameServiceResponse_t() {}
		NameServiceResponse_t(
			_In_ JSonDocument::GenericValue::Object Object
		) {
			DisplayName = FindAndGetString(Object, "DisplayName");
			Subject = FindAndGetUUID(Object, "Subject");

			RiotID = RiotID_t(FindAndGetString(Object, "GameName"), FindAndGetString(Object, "TagLine"));
		}

		inline const RiotID_t& GetRiotID() const {
			return RiotID;
		}

		std::string DisplayName;

		// PUUID
		UUID_t Subject;
		RiotID_t RiotID;
	};

	struct PartyPlayer_t {
		PartyPlayer_t() : Version(0) {}
		PartyPlayer_t(
			_In_ JSonDocument::GenericValue::Object Object
		) {
			Subject = FindAndGetUUID(Object, "Subject");
			Version = FindAndGetUInt64(Object, "Version");
			CurrentPartyID = FindAndGetString(Object, "CurrentPartyID");
		}

		// PUUID
		UUID_t Subject;
		std::uint64_t Version;
		std::string CurrentPartyID;
	};

	struct CompetitiveUpdates_t {
		struct Match_t {
			Match_t() : TierAfterUpdate(0),
				TierBeforeUpdate(0),
				RankedRatingAfterUpdate(0),
				RankedRatingBeforeUpdate(0),
				RankedRatingEarned(0),
				RankedRatingPerformanceBonus(0) {}

			Match_t(
				_In_ JSonDocument::GenericValue::Object Object
			) {
				MatchID = FindAndGetString(Object, "MatchID");
				MapID = FindAndGetString(Object, "MapID");
				SeasonID = FindAndGetUUID(Object, "SeasonID");
				MatchStartTime = CTime(FindAndGetUInt64(Object, "MatchStartTime"));
				TierAfterUpdate = static_cast<TierID>(FindAndGetUInt64(Object, "TierAfterUpdate"));
				TierBeforeUpdate = static_cast<TierID>(FindAndGetUInt64(Object, "TierBeforeUpdate"));
				RankedRatingAfterUpdate = FindAndGetUInt64(Object, "RankedRatingAfterUpdate");
				RankedRatingBeforeUpdate = FindAndGetUInt64(Object, "RankedRatingBeforeUpdate");
				RankedRatingEarned = FindAndGetUInt64(Object, "RankedRatingEarned");
				RankedRatingPerformanceBonus = FindAndGetUInt64(Object, "RankedRatingPerformanceBonus");
			}

			std::string MatchID;
			std::string MapID;
			UUID_t SeasonID;
			CTime MatchStartTime;
			TierID TierAfterUpdate;
			TierID TierBeforeUpdate;
			std::uint64_t RankedRatingAfterUpdate;
			std::uint64_t RankedRatingBeforeUpdate;
			std::uint64_t RankedRatingEarned;
			std::uint64_t RankedRatingPerformanceBonus;
		};

		CompetitiveUpdates_t() : Version(0) {}
		CompetitiveUpdates_t(
			_In_ JSonDocument::GenericValue::Object Object
		) {
			Subject = FindAndGetUUID(Object, "Subject");
			Version = FindAndGetUInt64(Object, "Version");

			if (Object.HasMember("Matches") && Object["Matches"].IsArray()) {
				auto MatchesArray = Object["Matches"].GetArray();

				for (auto& Match : MatchesArray) {
					if (Match.IsObject())
						Matches.emplace_back(Match.GetObject());
				}
			}
		}

		// PUUID
		UUID_t Subject;
		std::uint64_t Version;
		std::vector<Match_t> Matches;
	};
}

/////////////////////////////////////
// Unofficial API Structures
/////////////////////////////////////
namespace UnofficialAPIStructures {
	// https://valorant-api.com/v1/agents
	struct Agent_t {
		Agent_t() {}
		Agent_t(
			_In_ JSonDocument::GenericValue::Object Object
		) {
			UUID = FindAndGetUUID(Object, "uuid");
			DisplayName = FindAndGetString(Object, "displayName");

			if (Object.HasMember("backgroundGradientColors") && Object["backgroundGradientColors"].IsArray()) {
				auto BackgroundGradientColorsArray = Object["backgroundGradientColors"].GetArray();

				std::uint8_t i = 0;

				for (auto& ColorArrayValue : BackgroundGradientColorsArray) {
					if (i > 3) break;
					// comes as a string of hex characters like: "d3adb33f"
					if (!ColorArrayValue.IsString())
						continue;

					BackgroundGradientColors[i++] = HexStringToColor(ColorArrayValue.GetString());
				}
			}
		}

		// Agent UUID
		UUID_t UUID;
		std::string DisplayName;
		Color32_t BackgroundGradientColors[4];
	};

	// https://valorant-api.com/v1/maps
	struct Map_t {
		Map_t() {}
		Map_t(
			_In_ JSonDocument::GenericValue::Object Object
		) {
			UUID = FindAndGetUUID(Object, "uuid");
			DisplayName = FindAndGetString(Object, "displayName");
			MapUrl = FindAndGetString(Object, "mapUrl");
		}

		// !!!!! Not the same as MapID !!!!!
		// Map UUID
		UUID_t UUID;
		std::string DisplayName;

		// the same as MapID
		MapURL MapUrl;
	};


	// different from CompetitiveSeason_t, you're unable to get the competitive tier
	// through this
	struct Season_t {
		Season_t() : IsBeta(false), EpisodeNr(0), ActNr(0) {}
		Season_t(
			_In_ JSonDocument::GenericValue::Object Object
		) {
			UUID = FindAndGetUUID(Object, "uuid");
			DisplayName = FindAndGetString(Object, "displayName");
			AssetPath = FindAndGetString(Object, "assetPath");
			ParentUUID = FindAndGetUUID(Object, "parentUuid");
			StartTime = CTime(FindAndGetString(Object, "startTime"));
			EndTime = CTime(FindAndGetString(Object, "endTime"));

			// looks like:
			//		"ShooterGame/Content/Seasons/Season_CB_DataAsset"
			// or
			//		"ShooterGame/Content/Seasons/Season_Episode1_Act1_DataAsset"

			auto EpisodeNameStart = AssetPath.find("Episode");
			auto ActNameStart = AssetPath.find("Act");


			// Beta
			if (EpisodeNameStart == std::string::npos && ActNameStart == std::string::npos) {
				IsBeta = true;
				EpisodeNr = 0;
				ActNr = 0;
			}
			else if (EpisodeNameStart != std::string::npos && ActNameStart == std::string::npos) { // Episodes
				IsBeta = false;

				auto EpisodeNumberEnd = AssetPath.find('_', EpisodeNameStart);

				// - 1 because it includes \0 
				auto EpisodeNumberStart = ARRAYSIZE("Episode") - 1 + EpisodeNameStart;

				std::string EpisodeNumberStr(
					AssetPath.begin() + EpisodeNumberStart,
					AssetPath.begin() + EpisodeNumberEnd
				);

				EpisodeNr = static_cast<std::uint8_t>(std::stoul(EpisodeNumberStr));
				ActNr = 0;
			}
			else { // Acts
				IsBeta = false;
				auto EpisodeNumberEnd = AssetPath.find('_', EpisodeNameStart);

				// - 1 because it includes \0 
				auto EpisodeNumberStart = ARRAYSIZE("Episode") - 1 + EpisodeNameStart;

				std::string EpisodeNumberStr(
					AssetPath.begin() + EpisodeNumberStart,
					AssetPath.begin() + EpisodeNumberEnd
				);

				EpisodeNr = static_cast<std::uint8_t>(std::stoul(EpisodeNumberStr));

				auto ActNumberEnd = AssetPath.find('_', ActNameStart);

				// - 1 because it includes \0
				auto ActNumberStart = ARRAYSIZE("Act") - 1 + ActNameStart;

				std::string ActNumberStr(
					AssetPath.begin() + ActNumberStart,
					AssetPath.begin() + ActNumberEnd
				);

				ActNr = static_cast<std::uint8_t>(std::stoul(ActNumberStr));
			}
		}

		inline bool IsActive() const {
			CTime LocalTime = CTime::NowLocal();
			return LocalTime > StartTime && LocalTime < EndTime;
		}

		UUID_t UUID;
		std::string DisplayName;
		std::string AssetPath;
		UUID_t ParentUUID;
		CTime StartTime;
		CTime EndTime;
		// not part of the actual Season structure returned by valorant-api.com
		bool IsBeta;
		std::uint8_t EpisodeNr;
		std::uint8_t ActNr;
	};

	struct CompetitiveSeason_t {
		CompetitiveSeason_t() {}
		CompetitiveSeason_t(
			_In_ JSonDocument::GenericValue::Object Object
		) {
			UUID = FindAndGetUUID(Object, "uuid");
			SeasonUUID = FindAndGetUUID(Object, "seasonUuid");
			CompetitiveTeirUUID = FindAndGetUUID(Object, "competitiveTiersUuid");
			StartTime = CTime(FindAndGetString(Object, "startTime"));
			EndTime = CTime(FindAndGetString(Object, "endTime"));
			AssetPath = FindAndGetString(Object, "assetPath");
		}

		inline bool IsActive() const {
			CTime LocalTime = CTime::NowLocal();
			return LocalTime > StartTime && LocalTime < EndTime;
		}

		UUID_t UUID;
		UUID_t SeasonUUID;
		UUID_t CompetitiveTeirUUID;
		CTime StartTime;
		CTime EndTime;
		std::string AssetPath;
	};

	struct CompetitiveTier_t {
		struct Tier_t {
			Tier_t() : Tier(0) {}
			Tier_t(
				_In_ JSonDocument::GenericValue::Object Object
			) {
				Tier = static_cast<TierID>(FindAndGetUInt64(Object, "tier"));

				TierName = FindAndGetString(Object, "tierName");

				// TierName comes in all uppercase I don't like that.
				if (TierName.begin() != TierName.end() &&
					std::next(TierName.begin()) != TierName.end()) {
					std::transform(
						std::next(TierName.begin()),
						TierName.end(),
						std::next(TierName.begin()),
						[](const char Char) -> char {
							return static_cast<char>(std::tolower(Char));
						}
					);
				}

				DivisionName = FindAndGetString(Object, "divisionName");

				// DivisionName comes in all uppercase I don't like that.
				if (DivisionName.begin() != DivisionName.end() &&
					std::next(DivisionName.begin()) != DivisionName.end()) {
					std::transform(
						std::next(DivisionName.begin()),
						DivisionName.end(),
						std::next(DivisionName.begin()),
						[](const char Char) -> char {
							return static_cast<char>(std::tolower(Char));
						}
					);
				}

				Color = HexStringToColor(FindAndGetString(Object, "color"));
			}

			TierID Tier;
			std::string TierName;
			std::string DivisionName;
			Color32_t Color;
		};

		CompetitiveTier_t() {}
		CompetitiveTier_t(
			_In_ JSonDocument::GenericValue::Object Object
		) {
			UUID = FindAndGetUUID(Object, "uuid");

			if (Object.HasMember("tiers") && Object["tiers"].IsArray()) {
				auto TiersArray = Object["tiers"].GetArray();

				std::for_each(
					TiersArray.begin(),
					TiersArray.end(),
					[this](auto& JsonTier) -> void {
						Tiers.emplace_back(JsonTier.GetObject());
					}
				);
			}
		}

		// Competitive Tiers UUID
		// Can be used in conjunction with the CompetitiveSeason_t struct
		UUID_t UUID;

		std::vector<Tier_t> Tiers;
	};
}

////////////////////////////////////////
// HTTP helpers
////////////////////////////////////////

class CHTTPJSonRequest : public CHTTPRequest
{
public:
	CHTTPJSonRequest(
		_In_ const CHTTPConnection& Connection,
		_In_ const std::wstring& Verb,
		_In_ const std::wstring& TargetResource,
		_In_ const DWORD dwFlags = WINHTTP_FLAG_SECURE
	);

	CHTTPJSonRequest(
		_In_ const CHTTPConnection& Connection,
		_In_ const std::wstring& Verb,
		_In_ const HTTPResource_t& TargetResource,
		_In_ const DWORD dwFlags = WINHTTP_FLAG_SECURE
	);

	bool SendRequestGetJSon(
		_Out_ JSonDocument& JSonOut,
		_In_opt_ std::wstring AdditionalHeaders = std::wstring(),
		_In_opt_ std::string OptionalData = std::string()
	);
};

class CRiotLocalEndpointRequest : public CHTTPJSonRequest
{
public:
	CRiotLocalEndpointRequest(
		_In_ const CHTTPConnection& Connection,
		_In_ const std::wstring& Verb,
		_In_ const std::wstring& TargetResource
	);

	CRiotLocalEndpointRequest(
		_In_ const CHTTPConnection& Connection,
		_In_ const std::wstring& Verb,
		_In_ const HTTPResource_t& TargetResource
	);
};

class IRiotHTTPHeaders
{
public:
	// "Authorization: Basic base64_encode(riot:lockfile password)"
	// lockfile is found at: 
	// %localappdata%\Riot Games\Riot Client\Config\lockfile
	// process name:pid:port:password:protocol
	virtual const std::wstring& GetBasicAuthHeader() const = 0;

	// "Authorization: Bearer Entitlements["accessToken"]"
	virtual const std::wstring& GetTokenAuthHeader() const = 0;

	// "X-Riot-Entitlements-JWT: Entitlements["token"]"
	virtual const std::wstring& GetEntitlementHeader() const = 0;

	// "X-Riot-ClientVersion: Session[Str]["version"]"
	virtual const std::wstring& GetClientVersionHeader() const = 0;

	// "X-Riot-ClientPlatform: base64_encode(client platform)"
	virtual const std::wstring& GetClientPlatformHeader() const = 0;
};

class IRiotHTTPConnections : public IRiotHTTPHeaders
{
public:
	// url: localhost:(lockfile port)
	virtual const CHTTPConnection& GetLocalConnection() const = 0;

	// url: pd.(shard).a.pvp.net
	virtual const CHTTPConnection& GetPlayerDataConnection() const = 0;

	// url: glz-(region)-1.(shard).a.pvp.net
	virtual const CHTTPConnection& GetGLZConnection() const = 0;
};

class CRiotLockFile
{
protected:
	CRiotLockFile();

	inline const std::string& GetLockFilePath() const;
	inline const std::string& GetLockFileContents() const;
	inline const std::string& GetRiotClientProcessName() const;
	inline const std::string& GetRiotClientProcessIDString() const;
	inline const DWORD GetRiotClientProcessID() const;
	inline const std::string& GetLockFilePortString() const;
	inline const INTERNET_PORT GetLockFilePort() const;
	inline const std::string& GetLockFilePassword() const;
	inline const std::string& GetLockFileProtocol() const;
private:
	CFile m_File;
	std::string m_LockFilePath;
	std::string m_FileContents;
	std::string m_ProcessName;

	std::string m_ProcessIDStr;
	DWORD m_ProcessID;

	std::string m_PortStr;
	INTERNET_PORT m_Port;

	std::string m_Password;
	std::string m_Protocol;
};

class CRiotLocalEndpoint :
	public IRiotHTTPConnections,
	protected CRiotLockFile
{
protected:
	CRiotLocalEndpoint();

	// url: localhost:(lockfile port)
	virtual const CHTTPConnection& GetLocalConnection() const override final;

	// "Authorization: Basic base64_encode(riot:lockfile password)"
	// lockfile is found at: 
	// %localappdata%\Riot Games\Riot Client\Config\lockfile
	// contents: "process name:pid:port:password:protocol"
	virtual const std::wstring& GetBasicAuthHeader() const override final;

	// "Authorization: Bearer Entitlements["accessToken"]"
	virtual const std::wstring& GetTokenAuthHeader() const override final;

	// "X-Riot-Entitlements-JWT: Entitlements["token"]"
	virtual const std::wstring& GetEntitlementHeader() const override final;

	// "X-Riot-ClientVersion: Session[Str]["version"]"
	virtual const std::wstring& GetClientVersionHeader() const override final;

	// "X-Riot-ClientPlatform: base64_encode(client platform)"
	virtual const std::wstring& GetClientPlatformHeader() const override final;

	virtual const std::wstring& GetRegion() const;
	virtual const std::wstring& GetShard() const;

public:
	bool GetEntitlements(
		_Out_ RiotAPIStructure::RiotEntitlements_t& Entitlements
	) const;

	bool GetSession(
		_Out_ std::map<std::string, RiotAPIStructure::Session_t>& Sessions
	) const;

	inline const UUID_t& GetLocalPlayerUUID() const {
		return m_LocalPlayerUUID;
	}

protected:
	bool GetRiotClientVersionFromLogFile(
		_Out_ std::wstring& Version
	) const;

	bool GetRegionAndShardWithPUUID(
		_In_ const UUID_t& PUUID,
		_Out_ std::wstring& Region,
		_Out_ std::wstring& Shard
	) const;

private:
	CHTTPConnection m_LocalEndpointConnection;

	std::wstring m_BasicAuthHeaderString;
	std::wstring m_TokenAuthHeaderString;
	std::wstring m_EntitlementHeaderString;
	std::wstring m_ClientVersionHeaderString;
	std::wstring m_ClientPlatformString;

	UUID_t m_LocalPlayerUUID;

	std::wstring m_Region;
	std::wstring m_Shard;

	RiotAPIStructure::RiotEntitlements_t m_Entitlements;
	std::map<std::string, RiotAPIStructure::Session_t> m_Sessions;
};

class CRiotPVPEndpoint : public CRiotLocalEndpoint
{
protected:
	CRiotPVPEndpoint();
	// url: pd.(shard).a.pvp.net
	virtual const CHTTPConnection& GetPlayerDataConnection() const override final;
public:
	bool GetAccountXP(
		_In_ const UUID_t& PlayerUUID,
		_Out_ RiotAPIStructure::AccountXP_t& AccountXP
	) const;

	bool GetPlayerLoadout(
		_In_ const UUID_t& PlayerUUID,
		_Out_ RiotAPIStructure::PlayerLoadout_t& PlayerLoadout
	) const;

	bool GetPlayerMMR(
		_In_ const UUID_t& PlayerUUID,
		_Out_ RiotAPIStructure::PlayerMMR_t& PlayerMMR
	) const;

	bool GetNameFromPlayerUUID(
		_In_ const UUID_t& PlayerUUID,
		_Out_ RiotAPIStructure::NameServiceResponse_t& Name
	) const;

	std::map<UUID_t, RiotAPIStructure::NameServiceResponse_t> GetNamesFromPlayerUUIDList(
		_In_ const std::vector<UUID_t>& PlayerUUIDList
	) const;

	bool GetCompetitiveUpdates(
		_In_ const UUID_t& PlayerUUID,
		_In_ const std::size_t StartIndex,
		_In_ const std::size_t EndIndex,
		_In_ const ValorantQueueType_t Queue,
		_Out_ RiotAPIStructure::CompetitiveUpdates_t& CompetitiveUpdates
	) const;
private:
	CHTTPConnection m_PlayerDataEndpointConnection;
};

class CRiotGLZEndpoint : public CRiotPVPEndpoint
{
public:
	CRiotGLZEndpoint();

	// url: glz-(region)-1.(shard).a.pvp.net
	virtual const CHTTPConnection& GetGLZConnection() const override final;
public:
	bool GetPreGamePlayer(
		_In_ const UUID_t& PlayerUUID,
		_Out_ RiotAPIStructure::PreGamePlayer_t& PreGamePlayer
	) const;

	bool GetPreGameMatch(
		_In_ const UUID_t& PreGameMatchID,
		_Out_ RiotAPIStructure::PreGameMatch_t& PreGameMatch
	) const;

	bool GetCurrentGamePlayer(
		_In_ const UUID_t& PlayerUUID,
		_Out_ RiotAPIStructure::CurrentGamePlayer_t& CurrentGamePlayer
	) const;

	bool GetCurrentGameMatch(
		_In_ const UUID_t& CurentGameMatchID,
		_Out_ RiotAPIStructure::CurrentGameMatch_t& CurrentGameMatch
	) const;

	bool GetPartyPlayer(
		_In_ const UUID_t& PlayerUUID,
		_Out_ RiotAPIStructure::PartyPlayer_t& PartyPlayer
	) const;
private:
	CHTTPConnection m_GLZConnection;
};

class CUnofficialValorantAPI
{
public:
	CUnofficialValorantAPI();
protected:
	virtual const CHTTPConnection& GetUnofficialValorantAPIConnection() const final;
public:

	std::map<UUID_t, UnofficialAPIStructures::Season_t> GetSeasons() const;

	// Key is SeasonUUID and not a competitive season UUID
	std::map<UUID_t, UnofficialAPIStructures::CompetitiveSeason_t> GetCompetitiveSeasons() const;

	// Key is Tiers UUID
	std::map<UUID_t, UnofficialAPIStructures::CompetitiveTier_t> GetCompetitiveTiers() const;
	std::map<MapURL, UnofficialAPIStructures::Map_t> GetMaps() const;
	std::map<UUID_t, UnofficialAPIStructures::Agent_t> GetAgents() const;

protected:
	CHTTPConnection m_UnofficialValorantAPIConnection;
};

class CValorantAPI;
class CValorantAct;
class CValorantActPerformance : public IValorantActPerformance
{
	using _APISeasonalInfoTy = RiotAPIStructure::PlayerMMR_t::QueueSkills_t::SeasonalInfoBySeasonID_t;
public:
	CValorantActPerformance(const std::shared_ptr<const CValorantAPI> pValorantAPI);
	CValorantActPerformance(
		const std::shared_ptr<const CValorantAPI> pValorantAPI,
		const _APISeasonalInfoTy& APISeasonalInfo
	);

	virtual std::shared_ptr<const IValorantAct> GetAct() const;
	virtual const ValorantRank_t& GetRank() const;
	virtual bool IsRanked() const;
	virtual bool IsInPlacements() const;
	virtual std::uint64_t GetRankedRating() const;
	virtual std::uint64_t GetWins() const;
	virtual std::uint64_t GetLosses() const;
	virtual std::uint64_t GetNumGames() const;
	virtual float GetWinProbability() const;
	virtual bool HasLeaderboardRank() const;
	virtual std::uint64_t GetLeaderboardRank() const;
	virtual const ValorantRank_t& GetPeakRank() const;
	virtual const std::vector<std::pair<std::uint64_t, ValorantRank_t>>& GetWinsByRank() const;
private:
	std::shared_ptr<const CValorantAct> m_pAct;
	ValorantRank_t m_Rank;
	ValorantRank_t m_PeakRank;
	std::vector<
		std::pair<std::uint64_t, ValorantRank_t>
	> m_WinsByRank;

	std::uint64_t m_Wins;
	std::uint64_t m_Losses;
	std::uint64_t m_RankedRating;
	std::uint64_t m_LeaderboardRank;
	bool m_bIsRanked;
	bool m_bIsInPlacements;
	bool m_bHasLeaderboardRank;
};


class CValorantEpisode;
class CValorantAct : public IValorantAct
{
public:
	CValorantAct(
		const std::shared_ptr<const CValorantEpisode> pEpisode,
		const UUID_t& ActID,
		const std::uint64_t EpisodeNumber,
		const std::uint64_t ActNumber,
		const CTime& StartTime,
		const CTime& EndTime,
		const bool bBeta
	);

	virtual std::uint64_t GetEpisodeNumber() const;
	virtual std::uint64_t GetActNumber() const;
	virtual const CTime& GetStartTime() const;
	virtual const CTime& GetEndTime() const;
	virtual bool IsActive() const;
	virtual bool IsBeta() const;
	inline std::shared_ptr<const CValorantEpisode> GetEpisode() const;
	virtual const UUID_t& GetUUID() const;
private:
	const UUID_t m_ActID;
	const std::shared_ptr<const CValorantEpisode> m_pEpisode;
	const std::uint64_t m_EpisodeNumber;
	const std::uint64_t m_ActNumber;
	const CTime m_StartTime;
	const CTime m_EndTime;
	const bool m_bIsBeta;
};

class CValorantEpisode : public IValorantEpisode, public std::enable_shared_from_this<CValorantEpisode>
{
public:
	CValorantEpisode(
		const UUID_t& EpisodeID,
		const std::map<TierID, ValorantRank_t> CompetitiveRanks,
		const std::uint64_t EpisodeNumber,
		const CTime& StartTime,
		const CTime& EndTime
	);

	void AddActs(const std::vector<UnofficialAPIStructures::Season_t> Acts);
	virtual const UUID_t& GetUUID() const;
	virtual std::uint64_t GetEpisodeNumber() const;
	virtual bool IsActive() const;
	virtual const CTime& GetStartTime() const;
	virtual const CTime& GetEndTime() const;
	// Acts ordered by start date
	virtual const std::vector<std::shared_ptr<CValorantAct>>& GetActs() const;
	virtual const ValorantRank_t& GetRank(const TierID Rank) const;
private:
	const UUID_t m_EpisodeID;
	const std::uint64_t m_EpisodeNumber;
	const CTime m_StartTime;
	const CTime m_EndTime;

	const std::map<
		TierID,
		ValorantRank_t
	> m_CompetitiveRanks;

	std::vector<
		std::shared_ptr<CValorantAct>
	> m_Acts;
};

class CValorantAgent : public IValorantAgent
{
public:
	CValorantAgent(
		const UUID_t AgentUUID,
		const std::string& AgentName,
		const Color32_t AgentColor
	);

	virtual const UUID_t& GetUUID() const;
	virtual const std::string& GetName() const;
	virtual const Color32_t& GetColor() const;
private:
	const UUID_t m_UUID;
	const std::string m_Name;
	const Color32_t m_Color;
};

class CValorantMap : public IValorantMap
{
public:
	CValorantMap(
		const MapURL& URL,
		const std::string& Name
	);

	virtual const MapURL& GetURL() const;
	virtual const std::string& GetName() const;
private:
	const MapURL m_URL;
	const std::string m_Name;
};

class CValorantQueuePerformance : public IValorantQueuePerformance
{
	using _APIQueueSkillsTy = RiotAPIStructure::PlayerMMR_t::QueueSkills_t;
public:

	// for placing empty queue performances
	CValorantQueuePerformance(
		const std::shared_ptr<const CValorantAPI> pValorantAPI,
		const ValorantQueueType_t QueueType
	);

	CValorantQueuePerformance(
		const std::shared_ptr<const CValorantAPI> pValorantAPI,
		const ValorantQueueType_t QueueType,
		const _APIQueueSkillsTy& APIQueueSkills
	);

	virtual ValorantQueueType_t GetQueueType() const;

	inline CValorantActPerformance* GetActPerformance(const UUID_t& ActID);
	virtual const IValorantActPerformance* GetActPerformance(const UUID_t& ActID) const;

	inline CValorantActPerformance* GetActPerformance(const std::shared_ptr<const IValorantAct> pAct);
	virtual const IValorantActPerformance* GetActPerformance(const std::shared_ptr<const IValorantAct> pAct) const;

	inline CValorantActPerformance& GetCurrentActPerformance();
	virtual const IValorantActPerformance& GetCurrentActPerformance() const;

	inline CValorantActPerformance& GetPeakActPerformance();
	virtual const IValorantActPerformance& GetPeakActPerformance() const;
private:
	const ValorantQueueType_t m_QueueType;
	std::map<UUID_t, CValorantActPerformance> m_ActPerformances;

	// used to index Act performances
	UUID_t m_CurrentActPerformanceID;
	UUID_t m_PeakActPerformanceID;
};

class CValorantPlayer : public virtual IValorantPlayer
{
private:
	const std::shared_ptr<const CValorantAPI> m_pValorantAPI;
protected:
	inline const std::shared_ptr<const CValorantAPI>& GetValorantAPI() const {
		return m_pValorantAPI;
	}
public:
	// only used when getting the current match and current pre game
	CValorantPlayer(
		const std::shared_ptr<const CValorantAPI> pValorantAPI,
		const UUID_t PlayerID,
		const RiotID_t RiotID,
		const bool bIncognito,
		const std::uint64_t AccountLevel,
		const bool bHideAccountLevel
	);

	// shouldn't be used when you have a current match or a pre game
	CValorantPlayer(
		const std::shared_ptr<const CValorantAPI> pValorantAPI,
		const UUID_t PlayerID
	);

	virtual const UUID_t& GetPlayerID() const;
	virtual const RiotID_t& GetRiotID() const;
	virtual std::uint64_t GetAccountLevel() const;

	virtual bool IsLocalPlayer() const;
	// streamer mode / hidden name on valorant
	virtual bool IsIncognito() const;
	// hidden account level
	virtual bool IsHidingAccountLevel() const;
	// hidden ranked badge
	virtual bool IsActBadgeHidden() const;
	// hidden name on Immortal/Radiant leaderboard
	virtual bool IsLeaderboardAnonymized() const;

	inline CValorantQueuePerformance& GetQueuePerformance(const ValorantQueueType_t QueueType);
	virtual const IValorantQueuePerformance& GetQueuePerformance(const ValorantQueueType_t QueueType) const;

	virtual const IValorantActPerformance& GetCurrentCompetitivePerformance() const;

	// returns an act based on the highest rank a win is achieved
	virtual const IValorantActPerformance& GetPeakCompetitivePerformance() const;

	virtual UUID_t GetAgentSelectID() const;
	virtual UUID_t GetMatchID() const;
	virtual std::shared_ptr<IValorantAgentSelect> GetAgentSelect() const;
	virtual std::shared_ptr<IValorantMatch> GetMatch() const;
	virtual void UpdatePlayerMMR();
private:
	UUID_t m_PlayerID;
	RiotID_t m_RiotID;

	std::uint64_t m_AccountLevel;

	bool m_bLocalPlayer;

	// streamer mode / hidden name on valorant
	bool m_bIncognito;

	// hidden account level
	bool m_bHideAccountLevel;
private:
	// PlayerMMR
	// 
	// hidden ranked badge
	bool m_bActRankBadgeHidden;

	// hidden name on Immortal/Radiant leaderboard
	bool m_bLeaderboardAnonymized;

	std::map<ValorantQueueType_t, CValorantQueuePerformance> m_QueuePerformance;
};

class CValorantMatchPlayer : public CValorantPlayer, public IValorantMatchPlayer
{
public:
	CValorantMatchPlayer(
		const std::shared_ptr<const CValorantAPI> pValorantAPI,
		const UUID_t& PlayerID,
		const RiotID_t RiotID,
		const bool bIncognito,
		const std::uint64_t AccountLevel,
		const bool bHideAccountLevel,
		const UUID_t& AgentID,
		const TeamID_t Team
	);

	virtual bool HasAgent() const;
	virtual std::shared_ptr<const IValorantAgent> GetAgent() const;
	virtual TeamID_t GetTeam() const;
	virtual Color32_t GetTeamColor() const;
	virtual const UUID_t& GetPlayerID() const { return CValorantPlayer::GetPlayerID(); }
	virtual const RiotID_t& GetRiotID() const { return CValorantPlayer::GetRiotID(); }
	virtual bool IsLocalPlayer() const { return CValorantPlayer::IsLocalPlayer(); }
	virtual std::uint64_t GetAccountLevel() const { return CValorantPlayer::GetAccountLevel(); }
	virtual bool IsIncognito() const { return CValorantPlayer::IsIncognito(); }
	virtual bool IsHidingAccountLevel() const { return CValorantPlayer::IsHidingAccountLevel(); }
	virtual bool IsActBadgeHidden() const { return CValorantPlayer::IsActBadgeHidden(); }
	virtual bool IsLeaderboardAnonymized() const { return CValorantPlayer::IsLeaderboardAnonymized(); }
	virtual const IValorantQueuePerformance& GetQueuePerformance(const ValorantQueueType_t QueueType) const { return CValorantPlayer::GetQueuePerformance(QueueType); }
	virtual const IValorantActPerformance& GetCurrentCompetitivePerformance() const { return CValorantPlayer::GetCurrentCompetitivePerformance(); }
	virtual const IValorantActPerformance& GetPeakCompetitivePerformance() const { return CValorantPlayer::GetPeakCompetitivePerformance(); }
	virtual void UpdatePlayerMMR() { return CValorantPlayer::UpdatePlayerMMR(); }
	virtual UUID_t GetAgentSelectID() const { return CValorantPlayer::GetAgentSelectID(); }
	virtual std::shared_ptr<IValorantAgentSelect> GetAgentSelect() const { return CValorantPlayer::GetAgentSelect(); }
	virtual UUID_t GetMatchID() const { return CValorantPlayer::GetMatchID(); }
	virtual std::shared_ptr<IValorantMatch> GetMatch() const { return CValorantPlayer::GetMatch(); }

private:
	const std::shared_ptr<const CValorantAgent> m_pAgent;
	const TeamID_t m_Team;
};

class CValorantAgentSelect : public IValorantAgentSelect
{
public:
	CValorantAgentSelect(
		const std::shared_ptr<const CValorantAPI> pValorantAPI,
		const UUID_t& MatchID
	);

	virtual bool IsValid() const;
	virtual TeamID_t GetTeam() const;
	virtual std::vector<const IValorantMatchPlayer*> GetTeammates() const;
	virtual std::shared_ptr<const IValorantMap> GetMap() const;
private:
	UUID_t m_MatchID;
	TeamID_t m_Team;
	std::shared_ptr<const IValorantMap> m_pMap;
	std::vector<CValorantMatchPlayer> m_Teammates;
};

class CValorantMatch : public IValorantMatch
{
public:
	CValorantMatch(
		const std::shared_ptr<const CValorantAPI> pValorantAPI,
		const UUID_t& MatchID
	);

	virtual bool IsValid() const;
	virtual std::shared_ptr<const IValorantMap> GetMap() const;
	virtual std::vector<const IValorantMatchPlayer*> GetAttackers() const;
	virtual std::vector<const IValorantMatchPlayer*> GetDefenders() const;
	virtual std::vector<const IValorantMatchPlayer*> GetOtherPlayers() const;
private:
	UUID_t m_MatchID;
	std::shared_ptr<const IValorantMap> m_pMap;
	std::vector<CValorantMatchPlayer> m_Players;
};

class CValorantPlayer;
class CValorantAPI : public CRiotGLZEndpoint, public IValorantAPI, public std::enable_shared_from_this<CValorantAPI>
{
	friend class CValorantPlayer;
public:
	CValorantAPI();
	CValorantAPI(const CValorantAPI&) = delete;

	inline std::shared_ptr<const CValorantAgent> FindAgentWithUUID(
		const UUID_t& AgentUUID
	) const;

	inline std::shared_ptr<const CValorantMap> FindMapWithURL(
		const MapURL& URL
	) const;

	inline std::shared_ptr<const CValorantAct> GetAct(
		const UUID_t& ActID
	) const;

	inline std::shared_ptr<const CValorantAct> GetCurrentAct() const;
	inline const ValorantRank_t& GetUnrankedRank() const;
	inline const ValorantRank_t& GetPlacementsRank() const;
	virtual std::unique_ptr<IValorantPlayer> GetPlayer(const UUID_t& PlayerID);
	virtual std::unique_ptr<IValorantPlayer> GetLocalPlayer();
private:
	const std::shared_ptr<CUnofficialValorantAPI> m_pUnofficialAPIEndpoint;

	std::shared_ptr<const CValorantAct> m_CurrentAct;
	ValorantRank_t m_Unranked;
	ValorantRank_t m_PlacementsRank;

	// Agents by UUID
	std::shared_ptr<const CValorantAgent> m_pInvalidAgent;
	std::map<UUID_t, std::shared_ptr<const CValorantAgent>> m_Agents;

	std::shared_ptr<const CValorantMap> m_pInvalidMap;
	std::map<MapURL, std::shared_ptr<const CValorantMap>> m_Maps;

	std::map<
		UUID_t, // ActID
		std::shared_ptr<const CValorantAct>
	> m_Acts;

	std::map<
		UUID_t,
		std::shared_ptr<const CValorantEpisode>
	> m_Episodes;
};

///////////////////////////////////////////////////
// CHTTPJSonRequest
///////////////////////////////////////////////////

CHTTPJSonRequest::CHTTPJSonRequest(
	_In_ const CHTTPConnection& Connection,
	_In_ const std::wstring& Verb,
	_In_ const std::wstring& TargetResource,
	_In_ const DWORD dwFlags
) : CHTTPRequest(Connection, Verb, TargetResource, dwFlags) {}

CHTTPJSonRequest::CHTTPJSonRequest(
	_In_ const CHTTPConnection& Connection,
	_In_ const std::wstring& Verb,
	_In_ const HTTPResource_t& TargetResource,
	_In_ const DWORD dwFlags
) : CHTTPRequest(Connection, Verb, TargetResource, dwFlags) {}

bool CHTTPJSonRequest::SendRequestGetJSon(
	_Out_ JSonDocument& JSonOut,
	_In_opt_ std::wstring AdditionalHeaders,
	_In_opt_ std::string OptionalData
) {
	assert(AdditionalHeaders.length() <= std::numeric_limits<DWORD>::max());
	assert(OptionalData.length() <= std::numeric_limits<DWORD>::max());

	JSonOut = JSonDocument();

	this->SendRequest(
		AdditionalHeaders.data(),
		static_cast<DWORD>(AdditionalHeaders.length()),
		OptionalData.data(),
		static_cast<DWORD>(OptionalData.length())
	);

	if (!this->RecieveResponse() || this->GetStatusCode() != HTTP_STATUS_OK)
		return false;

	std::string Data = this->ReadDataAvailable();

	JSonOut.Parse(
		Data.c_str(),
		Data.length()
	);

	return true;
}

///////////////////////////////////////////////////
// CRiotLocalEndpointRequest
///////////////////////////////////////////////////

CRiotLocalEndpointRequest::CRiotLocalEndpointRequest(
	_In_ const CHTTPConnection& Connection,
	_In_ const std::wstring& Verb,
	_In_ const std::wstring& TargetResource
) : CHTTPJSonRequest(Connection, Verb, TargetResource) {
	// Ignore invalid cert
	ULONG Flags = SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
		SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
		SECURITY_FLAG_IGNORE_UNKNOWN_CA |
		SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

	WinHttpSetOption(
		GetRequestHandle(),
		WINHTTP_OPTION_SECURITY_FLAGS,
		&Flags,
		sizeof(Flags)
	);
}

CRiotLocalEndpointRequest::CRiotLocalEndpointRequest(
	_In_ const CHTTPConnection& Connection,
	_In_ const std::wstring& Verb,
	_In_ const HTTPResource_t& TargetResource
) : CHTTPJSonRequest(Connection, Verb, TargetResource) {
	ULONG Flags = SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
		SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
		SECURITY_FLAG_IGNORE_UNKNOWN_CA |
		SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

	WinHttpSetOption(
		GetRequestHandle(),
		WINHTTP_OPTION_SECURITY_FLAGS,
		&Flags,
		sizeof(Flags)
	);
}

///////////////////////////////////////////////////
// CRiotLockFile
///////////////////////////////////////////////////

static constexpr std::string_view RIOT_CLIENT_LOCKFILE_PATH = "Riot Games\\Riot Client\\Config\\";
static constexpr std::string_view RIOT_CLIENT_LOCKFILE_NAME = "lockfile";

CRiotLockFile::CRiotLockFile() {
	m_LockFilePath = GetLocalAppdataPath() + "\\";
	m_LockFilePath += RIOT_CLIENT_LOCKFILE_PATH;
	m_LockFilePath += RIOT_CLIENT_LOCKFILE_NAME;

	m_File = CFile(m_LockFilePath);
	m_FileContents = m_File.ReadToString();

	std::regex Search("[^:]+");
	std::sregex_iterator Words = std::sregex_iterator(
		m_FileContents.begin(),
		m_FileContents.end(),
		Search
	);

	m_ProcessName = (Words++)->str();
	m_ProcessIDStr = (Words++)->str();
	m_PortStr = (Words++)->str();
	m_Password = (Words++)->str();
	m_Protocol = (Words++)->str();

	m_ProcessID = std::stoul(m_ProcessIDStr);
	m_Port = static_cast<INTERNET_PORT>(std::stoul(m_PortStr));
}

inline const std::string& CRiotLockFile::GetLockFilePath() const {
	return m_LockFilePath;
}

inline const std::string& CRiotLockFile::GetLockFileContents() const {
	return m_FileContents;
}

inline const std::string& CRiotLockFile::GetRiotClientProcessName() const {
	return m_ProcessName;
}

inline const std::string& CRiotLockFile::GetRiotClientProcessIDString() const {
	return m_ProcessIDStr;
}

inline const DWORD CRiotLockFile::GetRiotClientProcessID() const {
	return m_ProcessID;
}

inline const std::string& CRiotLockFile::GetLockFilePortString() const {
	return m_PortStr;
}

inline const INTERNET_PORT CRiotLockFile::GetLockFilePort() const {
	return m_Port;
}

inline const std::string& CRiotLockFile::GetLockFilePassword() const {
	return m_Password;
}

inline const std::string& CRiotLockFile::GetLockFileProtocol() const {
	return m_Protocol;
}

///////////////////////////////////////////////////
// CRiotLocalEndpoint
///////////////////////////////////////////////////

static constexpr const wchar_t* RIOT_LOCAL_ENDPOINT_ADDRESS = L"localhost";
static constexpr const wchar_t* RIOT_LOCAL_ENDPOINT_USERAGENT = L"";

CRiotLocalEndpoint::CRiotLocalEndpoint() :
	CRiotLockFile(),
	m_LocalEndpointConnection(
		RIOT_LOCAL_ENDPOINT_ADDRESS,
		GetLockFilePort(),
		RIOT_LOCAL_ENDPOINT_USERAGENT
	)
{
	////////////////////////////////////////
	//                                    //
	// Initialize headers that we'll need //
	//                                    //
	////////////////////////////////////////

	// must initialize this before we get entitlements and 
	// session since we need this to access the local endpoint 
	m_BasicAuthHeaderString = L"Authorization: Basic " +
		base64_encode(L"riot:" + ConvertString<std::string, std::wstring>(GetLockFilePassword()));

	if (!GetEntitlements(m_Entitlements))
		throw std::runtime_error("Failed to get Entitlements");

	if (!GetSession(m_Sessions))
		throw std::runtime_error("Failed to get Sessions");

	m_LocalPlayerUUID = m_Entitlements.GetPUUID();
	m_TokenAuthHeaderString = L"Authorization: Bearer " + m_Entitlements.GetAccessToken();
	m_EntitlementHeaderString = L"X-Riot-Entitlements-JWT: " + m_Entitlements.GetToken();

	std::wstring RiotClientVersion;

	if (!GetRiotClientVersionFromLogFile(RiotClientVersion))
		throw std::runtime_error("Failed to get Riot client version");

	m_ClientVersionHeaderString = L"X-Riot-ClientVersion: " +
		RiotClientVersion;

	std::wstring PlatformVersion = L"{\r\n"
		L"\t\"platformType\": \"PC\",\r\n"
		L"\t\"platformOS\": \"Windows\",\r\n"
		L"\t\"platformOSVersion\": \"10.0.19042.1.256.64bit\",\r\n"
		L"\t\"platformChipset\": \"Unknown\"\r\n"
		L"}";

	m_ClientPlatformString = L"X-Riot-ClientPlatform: " +
		base64_encode(PlatformVersion);

	if (!GetRegionAndShardWithPUUID(m_Entitlements.GetPUUID(), m_Region, m_Shard))
		throw std::runtime_error("Failed to get region and shard");
}


const CHTTPConnection& CRiotLocalEndpoint::GetLocalConnection() const {
	return m_LocalEndpointConnection;
}

// "Authorization: Basic base64_encode(riot:lockfile password)"
// lockfile is found at: 
// %localappdata%\Riot Games\Riot Client\Config\lockfile
// contents: "process name:pid:port:password:protocol"
const std::wstring& CRiotLocalEndpoint::GetBasicAuthHeader() const {
	return m_BasicAuthHeaderString;
}

// "Authorization: Bearer Entitlements["accessToken"]"
const std::wstring& CRiotLocalEndpoint::GetTokenAuthHeader() const {
	return m_TokenAuthHeaderString;
}

// "X-Riot-Entitlements-JWT: Entitlements["token"]"
const std::wstring& CRiotLocalEndpoint::GetEntitlementHeader() const {
	return m_EntitlementHeaderString;
}

// "X-Riot-ClientVersion: Session[Str]["version"]"
const std::wstring& CRiotLocalEndpoint::GetClientVersionHeader() const {
	return m_ClientVersionHeaderString;
}

// "X-Riot-ClientPlatform: base64_encode(client platform)"
const std::wstring& CRiotLocalEndpoint::GetClientPlatformHeader() const {
	return m_ClientPlatformString;
}

const std::wstring& CRiotLocalEndpoint::GetRegion() const { return m_Region; }
const std::wstring& CRiotLocalEndpoint::GetShard() const { return m_Shard; }

bool CRiotLocalEndpoint::GetEntitlements(
	_Out_ RiotAPIStructure::RiotEntitlements_t& Entitlements
) const {
#define RIOT_ENTITLEMENT_METHOD_VERB L"GET"

	HTTPResource_t Resource({ L"entitlements", L"v1", L"token" });
	JSonDocument EntitlementsJSon;
	CRiotLocalEndpointRequest GetEntitlements(
		GetLocalConnection(),
		RIOT_ENTITLEMENT_METHOD_VERB,
		Resource
	);

	GetEntitlements.AddHeader(GetBasicAuthHeader(), WINHTTP_ADDREQ_FLAG_ADD);
	// make sure the request was sent successfully
	if (!GetEntitlements.SendRequestGetJSon(EntitlementsJSon)) {
		Entitlements = RiotAPIStructure::RiotEntitlements_t();
		return false;
	}

	assert(EntitlementsJSon.IsObject());
	Entitlements = RiotAPIStructure::RiotEntitlements_t(EntitlementsJSon.GetObject());
	return true;
}

bool CRiotLocalEndpoint::GetSession(
	_Out_ std::map<std::string, RiotAPIStructure::Session_t>& Sessions
) const {
#define RIOT_SESSION_METHOD_VERB L"GET"
	HTTPResource_t Resource({ L"product-session", L"v1", L"external-sessions" });
	CRiotLocalEndpointRequest SessionRequest(
		GetLocalConnection(),
		RIOT_SESSION_METHOD_VERB,
		Resource
	);

	SessionRequest.AddHeader(GetBasicAuthHeader());

	JSonDocument SessionJSon;

	Sessions = std::map<std::string, RiotAPIStructure::Session_t>();
	if (!SessionRequest.SendRequestGetJSon(SessionJSon)) {
		return false;
	}

	auto SessionsObject = SessionJSon.GetObject();

	for (auto& SessionObject : SessionsObject) {
		if (SessionObject.name.IsString() && SessionObject.value.IsObject()) {
			Sessions.emplace(
				SessionObject.name.GetString(),
				SessionObject.value.GetObject()
			);
		}
	}
	return true;
}

static constexpr const wchar_t* VALORANT_LOG_FILE_DIRECTORY = L"VALORANT\\Saved\\Logs\\";
static constexpr const wchar_t* VALORANT_SHOOTERGAME_LOG_FILE = L"ShooterGame.log";

bool CRiotLocalEndpoint::GetRiotClientVersionFromLogFile(
	_Out_ std::wstring& Version
) const {
	CFile ShooterGameLogFile(
		GetLocalAppdataPathW() + L"\\" +
		VALORANT_LOG_FILE_DIRECTORY +
		VALORANT_SHOOTERGAME_LOG_FILE
	);

	std::wstring FileContents = ShooterGameLogFile.ReadToStringW();

	static constexpr const wchar_t* VALORANT_GAME_VERSION_BRANCH_STR = L"Branch: ";
	auto BranchStart = FileContents.find(VALORANT_GAME_VERSION_BRANCH_STR) +
		std::char_traits<wchar_t>::length(VALORANT_GAME_VERSION_BRANCH_STR);

	auto BranchEnd = FileContents.find(L'\n', BranchStart) - 1;

	Version = std::wstring(
		FileContents.begin() + BranchStart,
		FileContents.begin() + BranchEnd
	);

	Version += L"-shipping-";

	static constexpr const wchar_t* VALORANT_GAME_VERSION_BUILD_VERSION_STR = L"Build version: ";
	auto BuildVersionStart = FileContents.find(VALORANT_GAME_VERSION_BUILD_VERSION_STR) +
		std::char_traits<wchar_t>::length(VALORANT_GAME_VERSION_BUILD_VERSION_STR);

	auto BuildVersionEnd = FileContents.find(L'\n', BuildVersionStart) - 1;

	Version += std::wstring(
		FileContents.begin() + BuildVersionStart,
		FileContents.begin() + BuildVersionEnd
	) + L"-";

	static constexpr const wchar_t* VALORANT_GAME_VERSION_CHANGELIST_STR = L"Changelist: ";
	auto ChangelistStart = FileContents.find(VALORANT_GAME_VERSION_CHANGELIST_STR) +
		std::char_traits<wchar_t>::length(VALORANT_GAME_VERSION_CHANGELIST_STR);

	auto ChangelistEnd = FileContents.find(L'\n', ChangelistStart) - 1;

	Version += std::wstring(
		FileContents.begin() + ChangelistStart,
		FileContents.begin() + ChangelistEnd
	);

	return true;
}

bool CRiotLocalEndpoint::GetRegionAndShardWithPUUID(
	_In_ const UUID_t& PUUID,
	_Out_ std::wstring& Region,
	_Out_ std::wstring& Shard
) const {
	Region = L"";
	Shard = L"";
	CFile ShooterGameLogFile(
		GetLocalAppdataPathW() +
		L"\\" + VALORANT_LOG_FILE_DIRECTORY +
		L"\\" + VALORANT_SHOOTERGAME_LOG_FILE
	);

	// This ugly thing will find a url that contains our region, shard and PUUID
	// in the log file
	std::wregex URLExpression(
		L"https:\\/\\/glz-([\\w]+?)-1.([\\w]+?).a.pvp.net.+?\\/" + PUUID.GetRawIDW()
	);

	std::wstring ShooterGameFileContents = ShooterGameLogFile.ReadToStringW();
	auto URLS = std::wsregex_iterator(
		ShooterGameFileContents.begin(),
		ShooterGameFileContents.end(),
		URLExpression
	);

	if (URLS == std::wsregex_iterator())
		return false;

	std::wstring URL = (*URLS).str();

	auto Start = URL.find(L'-') + 1;
	auto End = URL.find(L"a.pvp.net");

	std::wstring Shortened(
		URL.begin() + Start,
		URL.begin() + End
	);

	Region = std::wstring(
		Shortened.begin(),
		Shortened.begin() + Shortened.find(L'-')
	);

	Shard = std::wstring(
		Shortened.begin() + Shortened.find(L'.') + 1,
		Shortened.begin() + Shortened.rfind(L'.')
	);

	return true;
}

///////////////////////////////////////////////////
// CRiotPVPEndpoint
///////////////////////////////////////////////////

CRiotPVPEndpoint::CRiotPVPEndpoint() :
	CRiotLocalEndpoint(),
	// pd.(shard).a.pvp.net
	m_PlayerDataEndpointConnection(L"pd." + GetShard() + L".a.pvp.net")
{}

// url: pd.(shard).a.pvp.net
const CHTTPConnection& CRiotPVPEndpoint::GetPlayerDataConnection() const {
	return m_PlayerDataEndpointConnection;
}

bool CRiotPVPEndpoint::GetAccountXP(
	_In_ const UUID_t& PlayerUUID,
	_Out_ RiotAPIStructure::AccountXP_t& AccountXP
) const {
#define RIOT_ACCOUNT_XP_METHOD_VERB L"GET"

	HTTPResource_t Resource({ L"account-xp", L"v1", L"players", PlayerUUID.GetRawIDW() });

	CHTTPJSonRequest AccountXPRequest(
		GetPlayerDataConnection(),
		RIOT_ACCOUNT_XP_METHOD_VERB,
		Resource
	);

	AccountXPRequest.AddHeader(GetTokenAuthHeader());
	AccountXPRequest.AddHeader(GetEntitlementHeader());

	JSonDocument JsonOut;
	if (!AccountXPRequest.SendRequestGetJSon(JsonOut)) {
		AccountXP = RiotAPIStructure::AccountXP_t();
		return false;
	}

	AccountXP = RiotAPIStructure::AccountXP_t(JsonOut.GetObject());
	return true;
}

bool CRiotPVPEndpoint::GetPlayerLoadout(
	_In_ const UUID_t& PlayerUUID,
	_Out_ RiotAPIStructure::PlayerLoadout_t& PlayerLoadout
) const {
#define RIOT_PLAYER_LOADOUT_METHOD_VERB L"GET"

	HTTPResource_t Resource({
		L"personalization", L"v2", L"players",
		PlayerUUID.GetRawIDW(), L"playerloadout"
		});

	CHTTPJSonRequest PlayerLoadoutRequest(
		GetPlayerDataConnection(),
		RIOT_PLAYER_LOADOUT_METHOD_VERB,
		Resource
	);

	PlayerLoadoutRequest.AddHeader(GetTokenAuthHeader());
	PlayerLoadoutRequest.AddHeader(GetEntitlementHeader());

	JSonDocument JsonOut;
	if (!PlayerLoadoutRequest.SendRequestGetJSon(JsonOut)) {
		PlayerLoadout = RiotAPIStructure::PlayerLoadout_t();
		return false;
	}

	PlayerLoadout = RiotAPIStructure::PlayerLoadout_t(JsonOut.GetObject());
	return true;
}

bool CRiotPVPEndpoint::GetPlayerMMR(
	_In_ const UUID_t& PlayerUUID,
	_Out_ RiotAPIStructure::PlayerMMR_t& PlayerMMR
) const {
	// Resource: /mmr/v1/players/(PlayerUUID)
#define RIOT_PLAYERMMR_METHOD_VERB L"GET"

	HTTPResource_t Resource({
		L"mmr", L"v1", L"players", PlayerUUID.GetRawIDW()
		});

	CHTTPJSonRequest GetPlayerMMRRequest(
		GetPlayerDataConnection(),
		RIOT_PLAYERMMR_METHOD_VERB,
		Resource
	);

	GetPlayerMMRRequest.AddHeader(GetEntitlementHeader());
	GetPlayerMMRRequest.AddHeader(GetTokenAuthHeader());
	GetPlayerMMRRequest.AddHeader(GetClientVersionHeader());
	GetPlayerMMRRequest.AddHeader(GetClientPlatformHeader());

	JSonDocument JsonOut;
	if (!GetPlayerMMRRequest.SendRequestGetJSon(JsonOut)) {
		PlayerMMR = RiotAPIStructure::PlayerMMR_t();
		return false;
	}

	PlayerMMR = RiotAPIStructure::PlayerMMR_t(JsonOut.GetObject());
	return true;
}

bool CRiotPVPEndpoint::GetNameFromPlayerUUID(
	_In_ const UUID_t& PlayerUUID,
	_Out_ RiotAPIStructure::NameServiceResponse_t& Name
) const {
	Name = RiotAPIStructure::NameServiceResponse_t();

	std::map<UUID_t, RiotAPIStructure::NameServiceResponse_t> Names = GetNamesFromPlayerUUIDList({ PlayerUUID });

	if (!Names.size())
		return false;

	Name = std::move(Names.begin()->second);
	return true;
}

std::map<UUID_t, RiotAPIStructure::NameServiceResponse_t> CRiotPVPEndpoint::GetNamesFromPlayerUUIDList(
	_In_ const std::vector<UUID_t>& PlayerUUIDList
) const {
#define RIOT_NAME_SERVICE_METHOD_VERB L"PUT"
	HTTPResource_t Resource({ L"name-service", L"v2", L"players" });
	CHTTPJSonRequest NamesFromPlayerUUIDListRequest(
		GetPlayerDataConnection(),
		RIOT_NAME_SERVICE_METHOD_VERB,
		Resource
	);

	NamesFromPlayerUUIDListRequest.AddHeader(GetEntitlementHeader());
	NamesFromPlayerUUIDListRequest.AddHeader(GetTokenAuthHeader());

	std::string utf8Body = "[";
	std::for_each(
		PlayerUUIDList.begin(),
		PlayerUUIDList.end(),
		[&](const UUID_t& PlayerUUID) -> void {
			utf8Body += std::vformat("\"{}\",", std::make_format_args(PlayerUUID.GetRawID()));
		}
	);

	utf8Body.pop_back(); // pop the last comma
	utf8Body += "]";

	std::map<UUID_t, RiotAPIStructure::NameServiceResponse_t> Names;
	JSonDocument JsonOut;

	assert(utf8Body.length() <= std::numeric_limits<DWORD>::max());

	if (!NamesFromPlayerUUIDListRequest.SendRequestGetJSon(
		JsonOut,
		std::wstring(),
		utf8Body
	)) {
		return Names;
	}

	if (JsonOut.IsArray()) {
		auto NamesArray = JsonOut.GetArray();

		std::for_each(
			NamesArray.begin(),
			NamesArray.end(),
			[&Names](JSonDocument::GenericValue& NameValue) -> void {
				JSonDocument::GenericValue::Object Object = NameValue.GetObject();
				if (Object.HasMember("Subject") && Object["Subject"].IsString()) {
					Names.emplace(FindAndGetUUID(Object, "Subject"), Object);
				}
			}
		);
	}

	return Names;
}

bool CRiotPVPEndpoint::GetCompetitiveUpdates(
	_In_ const UUID_t& PlayerUUID,
	_In_ const std::size_t StartIndex,
	_In_ const std::size_t EndIndex,
	_In_ const ValorantQueueType_t Queue,
	_Out_ RiotAPIStructure::CompetitiveUpdates_t& CompetitiveUpdates
) const {
#define RIOT_COMPETITIVE_UPDATES__METHOD_VERB L"GET"

	HTTPResource_t Resource(
		// Path
		{
			L"mmr", L"v1", L"players",
			PlayerUUID.GetRawIDW(), L"competitiveupdates"
		},
		// Query Key Value Pairs
		{
			{ L"startIndex", std::to_wstring(StartIndex) },
			{ L"endIndex", std::to_wstring(EndIndex) },
			{ L"queue", ValorantQueueTypeToStringW(Queue) }
		}
		);

	CHTTPJSonRequest GetCompetitiveUpdatesRequest(
		GetPlayerDataConnection(),
		RIOT_COMPETITIVE_UPDATES__METHOD_VERB,
		Resource
	);

	GetCompetitiveUpdatesRequest.AddHeader(GetEntitlementHeader());
	GetCompetitiveUpdatesRequest.AddHeader(GetTokenAuthHeader());
	GetCompetitiveUpdatesRequest.AddHeader(GetClientPlatformHeader());

	JSonDocument JsonOut;
	if (!GetCompetitiveUpdatesRequest.SendRequestGetJSon(JsonOut)) {
		CompetitiveUpdates = RiotAPIStructure::CompetitiveUpdates_t();
		return false;
	}

	CompetitiveUpdates = RiotAPIStructure::CompetitiveUpdates_t(JsonOut.GetObject());
	return true;
}

///////////////////////////////////////////////////
// CRiotGLZEndpoint
///////////////////////////////////////////////////

CRiotGLZEndpoint::CRiotGLZEndpoint() :
	CRiotPVPEndpoint(),
	// glz-(region)-1.(shard).a.pvp.net
	m_GLZConnection(L"glz-" + GetRegion() + L"-1." + GetShard() + L".a.pvp.net")
{ }

// url: glz-(region)-1.(shard).a.pvp.net
const CHTTPConnection& CRiotGLZEndpoint::GetGLZConnection() const {
	return m_GLZConnection;
}

bool CRiotGLZEndpoint::GetPreGamePlayer(
	_In_ const UUID_t& PlayerUUID,
	_Out_ RiotAPIStructure::PreGamePlayer_t& PreGamePlayer
) const {
	// Resource: pregame/v1/players/(PlayerUUID)
#define RIOT_PREGAME_PLAYER_METHOD_VERB L"GET"

	HTTPResource_t Resource({
		L"pregame", L"v1", L"players", PlayerUUID.GetRawIDW()
		});

	CHTTPJSonRequest PreGamePlayerRequest(
		GetGLZConnection(),
		RIOT_PREGAME_PLAYER_METHOD_VERB,
		Resource
	);

	PreGamePlayerRequest.AddHeader(GetEntitlementHeader());
	PreGamePlayerRequest.AddHeader(GetTokenAuthHeader());
	JSonDocument JsonOut;
	if (!PreGamePlayerRequest.SendRequestGetJSon(JsonOut)) {
		PreGamePlayer = RiotAPIStructure::PreGamePlayer_t();
		return false;
	}

	PreGamePlayer = RiotAPIStructure::PreGamePlayer_t(JsonOut.GetObject());
	return true;
}

bool CRiotGLZEndpoint::GetPreGameMatch(
	_In_ const UUID_t& PreGameMatchID,
	_Out_ RiotAPIStructure::PreGameMatch_t& PreGameMatch
) const {
	// Resource: /pregame/v1/matches/(PreGameMatchID)
#define RIOT_PREGAME_MATCH_METHOD_VERB L"GET"

	HTTPResource_t Resource({
		L"pregame", L"v1", L"matches", PreGameMatchID.GetRawIDW()
		});

	CHTTPJSonRequest PreGameMatchRequest(
		GetGLZConnection(),
		RIOT_PREGAME_MATCH_METHOD_VERB,
		Resource
	);

	PreGameMatchRequest.AddHeader(GetEntitlementHeader());
	PreGameMatchRequest.AddHeader(GetTokenAuthHeader());

	JSonDocument JsonOut;
	if (!PreGameMatchRequest.SendRequestGetJSon(JsonOut)) {
		PreGameMatch = RiotAPIStructure::PreGameMatch_t();
		return false;
	}

	PreGameMatch = RiotAPIStructure::PreGameMatch_t(JsonOut.GetObject());
	return true;
}

bool CRiotGLZEndpoint::GetCurrentGamePlayer(
	_In_ const UUID_t& PlayerUUID,
	_Out_ RiotAPIStructure::CurrentGamePlayer_t& CurrentGamePlayer
) const {
	// Resource: /core-game/v1/players/(PlayerUUID)
#define RIOT_CURRENTGAME_PLAYER_METHOD_VERB L"GET"

	HTTPResource_t Resource({
		L"core-game", L"v1", L"players", PlayerUUID.GetRawIDW()
		});

	CHTTPJSonRequest CurrentGamePlayerRequest(
		GetGLZConnection(),
		RIOT_CURRENTGAME_PLAYER_METHOD_VERB,
		Resource
	);

	CurrentGamePlayerRequest.AddHeader(GetEntitlementHeader());
	CurrentGamePlayerRequest.AddHeader(GetTokenAuthHeader());

	JSonDocument JsonOut;
	if (!CurrentGamePlayerRequest.SendRequestGetJSon(JsonOut)) {
		CurrentGamePlayer = RiotAPIStructure::CurrentGamePlayer_t();
		return false;
	}

	CurrentGamePlayer = RiotAPIStructure::CurrentGamePlayer_t(JsonOut.GetObject());
	return true;
}

bool CRiotGLZEndpoint::GetCurrentGameMatch(
	_In_ const UUID_t& CurentGameMatchID,
	_Out_ RiotAPIStructure::CurrentGameMatch_t& CurrentGameMatch
) const {
	// Resource: /core-game/v1/matches/(CurentGameMatchID)
#define RIOT_CURRENTGAME_MATCH_METHOD_VERB L"GET"

	HTTPResource_t Resource({
		L"core-game", L"v1", L"matches", CurentGameMatchID.GetRawIDW()
		});

	CHTTPJSonRequest CurrentGameMatchRequest(
		GetGLZConnection(),
		RIOT_CURRENTGAME_MATCH_METHOD_VERB,
		Resource
	);

	CurrentGameMatchRequest.AddHeader(GetEntitlementHeader());
	CurrentGameMatchRequest.AddHeader(GetTokenAuthHeader());

	JSonDocument JsonOut;
	if (!CurrentGameMatchRequest.SendRequestGetJSon(JsonOut)) {
		CurrentGameMatch = RiotAPIStructure::CurrentGameMatch_t();
		return false;
	}

	CurrentGameMatch = RiotAPIStructure::CurrentGameMatch_t(JsonOut.GetObject());
	return true;
}

bool CRiotGLZEndpoint::GetPartyPlayer(
	_In_ const UUID_t& PlayerUUID,
	_Out_ RiotAPIStructure::PartyPlayer_t& PartyPlayer
) const {
	// Resource: /parties/v1/players/(PlayerUUID)
#define RIOT_PARTYPLAYER_METHOD_VERB L"GET"

	HTTPResource_t Resource({
		L"parties", L"v1", L"players", PlayerUUID.GetRawIDW()
		});

	CHTTPJSonRequest PartyPlayerRequest(
		GetGLZConnection(),
		RIOT_PARTYPLAYER_METHOD_VERB,
		Resource
	);

	PartyPlayerRequest.AddHeader(GetEntitlementHeader());
	PartyPlayerRequest.AddHeader(GetTokenAuthHeader());
	PartyPlayerRequest.AddHeader(GetClientVersionHeader());

	JSonDocument JsonOut;
	if (!PartyPlayerRequest.SendRequestGetJSon(JsonOut)) {
		PartyPlayer = RiotAPIStructure::PartyPlayer_t();
		return false;
	}

	PartyPlayer = RiotAPIStructure::PartyPlayer_t(JsonOut.GetObject());
	return true;
}

///////////////////////////////////////////////////
// CUnofficialValorantAPI
///////////////////////////////////////////////////

CUnofficialValorantAPI::CUnofficialValorantAPI() :
	m_UnofficialValorantAPIConnection(L"valorant-api.com")
{}

const CHTTPConnection& CUnofficialValorantAPI::GetUnofficialValorantAPIConnection() const {
	return m_UnofficialValorantAPIConnection;
}

std::map<UUID_t, UnofficialAPIStructures::Season_t> CUnofficialValorantAPI::GetSeasons() const {
#define UNOFFICIALAPI_GET_SEASONS_METHOD_VERB L"GET"

	HTTPResource_t Resource({ L"v1", L"seasons" });

	CHTTPJSonRequest GetSeasonsRequest(
		GetUnofficialValorantAPIConnection(),
		UNOFFICIALAPI_GET_SEASONS_METHOD_VERB,
		Resource
	);

	std::map<UUID_t, UnofficialAPIStructures::Season_t> Seasons;
	JSonDocument JsonOut;
	if (GetSeasonsRequest.SendRequestGetJSon(JsonOut)) {
		if (JsonOut.HasMember("data") && JsonOut["data"].IsArray()) {
			auto SeasonsDataArray = JsonOut["data"].GetArray();
			for (auto& Season : SeasonsDataArray) {
				Seasons.emplace(
					FindAndGetUUID(Season.GetObject(), "uuid"),
					Season.GetObject()
				);
			}
		}
	}

	return Seasons;
}

std::map<UUID_t, UnofficialAPIStructures::CompetitiveSeason_t> CUnofficialValorantAPI::GetCompetitiveSeasons() const {
#define UNOFFICIALAPI_GET_COMPETITIVESEASONS_METHOD_VERB L"GET"
	HTTPResource_t Resource({ L"v1", L"seasons", L"competitive" });

	CHTTPJSonRequest GetCompetitiveSeasonsRequest(
		GetUnofficialValorantAPIConnection(),
		UNOFFICIALAPI_GET_COMPETITIVESEASONS_METHOD_VERB,
		Resource
	);

	std::map<UUID_t, UnofficialAPIStructures::CompetitiveSeason_t> Seasons;
	JSonDocument JsonOut;
	if (GetCompetitiveSeasonsRequest.SendRequestGetJSon(JsonOut)) {
		if (JsonOut.HasMember("data") && JsonOut["data"].IsArray()) {
			auto CompetitiveSeasonDataArray = JsonOut["data"].GetArray();
			for (auto& CompetitiveSeason : CompetitiveSeasonDataArray) {
				Seasons.emplace(
					FindAndGetUUID(CompetitiveSeason.GetObject(), "seasonUuid"),
					CompetitiveSeason.GetObject()
				);
			}
		}
	}
	return Seasons;
}

std::map<UUID_t, UnofficialAPIStructures::CompetitiveTier_t> CUnofficialValorantAPI::GetCompetitiveTiers() const {
#define UNOFFICIALAPI_GET_COMPETITIVETIERS_METHOD_VERB L"GET"

	HTTPResource_t Resource({ L"v1", L"competitivetiers" });

	CHTTPJSonRequest GetCompetitiveTiersRequest(
		GetUnofficialValorantAPIConnection(),
		UNOFFICIALAPI_GET_COMPETITIVETIERS_METHOD_VERB,
		Resource
	);

	std::map<UUID_t, UnofficialAPIStructures::CompetitiveTier_t> Tiers;
	JSonDocument JsonOut;
	if (GetCompetitiveTiersRequest.SendRequestGetJSon(JsonOut)) {
		if (JsonOut.HasMember("data") && JsonOut["data"].IsArray()) {
			auto CompetitiveTiersDataArray = JsonOut["data"].GetArray();
			for (auto& CompetitiveTiers : CompetitiveTiersDataArray) {
				Tiers.emplace(
					FindAndGetUUID(CompetitiveTiers.GetObject(), "uuid"),
					CompetitiveTiers.GetObject()
				);
			}
		}
	}
	return Tiers;
}

std::map<MapURL, UnofficialAPIStructures::Map_t> CUnofficialValorantAPI::GetMaps() const {
#define UNOFFICIALAPI_GET_MAPS_METHOD_VERB L"GET"
	HTTPResource_t Resource({ L"v1", L"maps" });
	CHTTPJSonRequest GetMapsRequest(
		GetUnofficialValorantAPIConnection(),
		UNOFFICIALAPI_GET_MAPS_METHOD_VERB,
		Resource
	);

	std::map<MapURL, UnofficialAPIStructures::Map_t> Maps;

	JSonDocument JsonOut;
	if (GetMapsRequest.SendRequestGetJSon(JsonOut)) {
		if (JsonOut.HasMember("data") && JsonOut["data"].IsArray()) {

			auto MapDataArray = JsonOut["data"].GetArray();
			for (auto& Map : MapDataArray) {
				Maps.emplace(
					FindAndGetString(Map.GetObject(), "mapUrl"),
					Map.GetObject()
				);
			}
		}
	}

	return Maps;
}

std::map<UUID_t, UnofficialAPIStructures::Agent_t> CUnofficialValorantAPI::GetAgents() const {
#define UNOFFICIALAPI_GET_AGENTS_METHOD_VERB L"GET"
	HTTPResource_t Resource({ L"v1", L"agents" });

	CHTTPJSonRequest GetAngentsRequest(
		GetUnofficialValorantAPIConnection(),
		UNOFFICIALAPI_GET_AGENTS_METHOD_VERB,
		Resource
	);

	std::map<UUID_t, UnofficialAPIStructures::Agent_t> Agents;

	JSonDocument JsonOut;
	if (GetAngentsRequest.SendRequestGetJSon(JsonOut)) {
		if (JsonOut.HasMember("data") && JsonOut["data"].IsArray()) {

			auto AgentDataArray = JsonOut["data"].GetArray();
			for (auto& Agent : AgentDataArray) {
				auto AgentObject = Agent.GetObject();

				// Skip over non playable characters
				if (!FindAndGetBool(AgentObject, "isPlayableCharacter"))
					continue;

				Agents.emplace(
					FindAndGetUUID(AgentObject, "uuid"),
					AgentObject
				);
			}
		}
	}

	return Agents;
}

///////////////////////////////////////////////////
// CValorantPlayerRank
///////////////////////////////////////////////////

CValorantActPerformance::CValorantActPerformance(const std::shared_ptr<const CValorantAPI> pValorantAPI) {
	m_pAct = pValorantAPI->GetCurrentAct();
	m_Wins = 0;
	m_Losses = 0;
	m_RankedRating = 0;
	m_LeaderboardRank = 0;
	m_bIsRanked = false;
	m_bIsInPlacements = false;
	m_bHasLeaderboardRank = false;
	m_Rank = pValorantAPI->GetUnrankedRank();
	m_PeakRank = pValorantAPI->GetUnrankedRank();
}

CValorantActPerformance::CValorantActPerformance(
	const std::shared_ptr<const CValorantAPI> pValorantAPI,
	const _APISeasonalInfoTy& APISeasonalInfo
) {
	std::shared_ptr<const CValorantAct> pAct = pValorantAPI->GetAct(APISeasonalInfo.SeasonID);
	std::shared_ptr<const CValorantEpisode> pEpisode = pAct->GetEpisode();
	m_pAct = pAct;
	m_Wins = APISeasonalInfo.NumberOfWinsWithPlacements;
	m_Losses = APISeasonalInfo.NumberOfGames - APISeasonalInfo.NumberOfWinsWithPlacements;
	m_RankedRating = APISeasonalInfo.RankedRating;
	m_LeaderboardRank = APISeasonalInfo.LeaderboardRank;
	m_bIsRanked = APISeasonalInfo.CompetitiveTier != 0;
	m_bIsInPlacements = !m_bIsRanked && APISeasonalInfo.NumberOfGames != 0;
	m_bHasLeaderboardRank = APISeasonalInfo.LeaderboardRank != 0;

	if (m_bIsRanked) {
		m_Rank = pEpisode->GetRank(APISeasonalInfo.CompetitiveTier);
	}
	else if (m_bIsInPlacements) {
		m_Rank = pValorantAPI->GetPlacementsRank();
	}
	else { // unranked
		m_Rank = pValorantAPI->GetUnrankedRank();
	}

	m_PeakRank = m_Rank;
	for (const std::pair<const TierID, std::uint64_t>& WinsByTierPair : APISeasonalInfo.WinsByTier) {
		const std::uint64_t Wins = WinsByTierPair.second;
		const ValorantRank_t& CurRank = pEpisode->GetRank(WinsByTierPair.first);

		m_WinsByRank.emplace_back(Wins, CurRank);

		if (CurRank >= m_PeakRank)
			m_PeakRank = CurRank;
	}
}

std::shared_ptr<const IValorantAct> CValorantActPerformance::GetAct() const {
	return m_pAct;
}

const ValorantRank_t& CValorantActPerformance::GetRank() const {
	return m_Rank;
}

bool CValorantActPerformance::IsRanked() const {
	return m_bIsRanked;
}

bool CValorantActPerformance::IsInPlacements() const {
	return m_bIsInPlacements;
}

std::uint64_t CValorantActPerformance::GetRankedRating() const {
	return m_RankedRating;
}

std::uint64_t CValorantActPerformance::GetWins() const {
	return m_Wins;
}

std::uint64_t CValorantActPerformance::GetLosses() const {
	return m_Losses;
}

std::uint64_t CValorantActPerformance::GetNumGames() const {
	return m_Wins + m_Losses;
}

float CValorantActPerformance::GetWinProbability() const {
	return static_cast<float>(GetWins()) / static_cast<float>(GetNumGames());
}

bool CValorantActPerformance::HasLeaderboardRank() const {
	return m_bHasLeaderboardRank;
}

std::uint64_t CValorantActPerformance::GetLeaderboardRank() const {
	return m_LeaderboardRank;
}

const ValorantRank_t& CValorantActPerformance::GetPeakRank() const {
	return m_PeakRank;
}

const std::vector<std::pair<std::uint64_t, ValorantRank_t>>& CValorantActPerformance::GetWinsByRank() const {
	return m_WinsByRank;
}

///////////////////////////////////////////////////
// CValorantAct
///////////////////////////////////////////////////
CValorantAct::CValorantAct(
	const std::shared_ptr<const CValorantEpisode> pEpisode,
	const UUID_t& ActID,
	const std::uint64_t EpisodeNumber,
	const std::uint64_t ActNumber,
	const CTime& StartTime,
	const CTime& EndTime,
	const bool bBeta
) : m_ActID(ActID),
m_pEpisode(pEpisode),
m_EpisodeNumber(EpisodeNumber),
m_ActNumber(ActNumber),
m_StartTime(StartTime),
m_EndTime(EndTime),
m_bIsBeta(bBeta) {}

std::uint64_t CValorantAct::GetEpisodeNumber() const {
	return m_EpisodeNumber;
}

std::uint64_t CValorantAct::GetActNumber() const {
	return m_ActNumber;
}

const CTime& CValorantAct::GetStartTime() const {
	return m_StartTime;
}

const CTime& CValorantAct::GetEndTime() const {
	return m_EndTime;
}

bool CValorantAct::IsActive() const {
	CTime Now = CTime::Now();

	return m_StartTime <= Now && m_EndTime >= Now;
}

bool CValorantAct::IsBeta() const {
	return m_bIsBeta;
}

inline std::shared_ptr<const CValorantEpisode> CValorantAct::GetEpisode() const {
	return m_pEpisode;
}

const UUID_t& CValorantAct::GetUUID() const {
	return m_ActID;
}

///////////////////////////////////////////////////
// CValorantEpisode
///////////////////////////////////////////////////

CValorantEpisode::CValorantEpisode(
	const UUID_t& EpisodeID,
	const std::map<TierID, ValorantRank_t> CompetitiveRanks,
	const std::uint64_t EpisodeNumber,
	const CTime& StartTime,
	const CTime& EndTime
) : m_EpisodeID(EpisodeID),
m_CompetitiveRanks(CompetitiveRanks),
m_EpisodeNumber(EpisodeNumber),
m_StartTime(StartTime),
m_EndTime(EndTime) {}

void CValorantEpisode::AddActs(const std::vector<UnofficialAPIStructures::Season_t> Acts) {
	std::for_each(
		Acts.begin(),
		Acts.end(),
		[this](const UnofficialAPIStructures::Season_t& Act) -> void {
			m_Acts.emplace_back(
				std::make_shared<CValorantAct>(
					shared_from_this(),
					Act.UUID,
					Act.EpisodeNr,
					Act.ActNr,
					Act.StartTime,
					Act.EndTime,
					Act.IsBeta
				)
			);
		}
	);

	std::sort(
		m_Acts.begin(),
		m_Acts.end(),
		[](std::shared_ptr<IValorantAct> A, std::shared_ptr<IValorantAct> B) -> bool {
			return A->GetStartTime() < B->GetStartTime();
		}
	);
}

const UUID_t& CValorantEpisode::GetUUID() const {
	return m_EpisodeID;
}

std::uint64_t CValorantEpisode::GetEpisodeNumber() const {
	return m_EpisodeNumber;
}

bool CValorantEpisode::IsActive() const {
	CTime Now = CTime::Now();

	return Now >= m_StartTime && Now <= m_EndTime;
}

const CTime& CValorantEpisode::GetStartTime() const {
	return m_StartTime;
}

const CTime& CValorantEpisode::GetEndTime() const {
	return m_EndTime;
}

// Acts ordered by start date
const std::vector<std::shared_ptr<CValorantAct>>& CValorantEpisode::GetActs() const {
	return m_Acts;
}

const ValorantRank_t& CValorantEpisode::GetRank(const TierID Rank) const {
	using _CompetitiveRanksIteratorTy = std::map<
		TierID,
		ValorantRank_t
	>::const_iterator;

	_CompetitiveRanksIteratorTy RankIt = m_CompetitiveRanks.find(Rank);
	if (RankIt == m_CompetitiveRanks.cend())
		throw std::invalid_argument("Invalid Rank");

	return RankIt->second;
}

///////////////////////////////////////////////////
// CValorantAgent
///////////////////////////////////////////////////
CValorantAgent::CValorantAgent(
	const UUID_t AgentUUID,
	const std::string& AgentName,
	const Color32_t AgentColor
) : m_UUID(AgentUUID),
m_Name(AgentName),
m_Color(AgentColor) {}

const UUID_t& CValorantAgent::GetUUID() const {
	return m_UUID;
}

const std::string& CValorantAgent::GetName() const {
	return m_Name;
}

const Color32_t& CValorantAgent::GetColor() const {
	return m_Color;
}

///////////////////////////////////////////////////
// CValorantMap
///////////////////////////////////////////////////
CValorantMap::CValorantMap(
	const MapURL& URL,
	const std::string& Name
) : m_URL(URL), m_Name(Name) {}


const MapURL& CValorantMap::GetURL() const {
	return m_URL;
}

const std::string& CValorantMap::GetName() const {
	return m_Name;
}

///////////////////////////////////////////////////
// CValorantQueuePerformance
///////////////////////////////////////////////////
CValorantQueuePerformance::CValorantQueuePerformance(
	const std::shared_ptr<const CValorantAPI> pValorantAPI,
	const ValorantQueueType_t QueueType
) : m_QueueType(QueueType) {
	std::shared_ptr<const IValorantAct> pCurrentAct = pValorantAPI->GetCurrentAct();
	m_ActPerformances.emplace(pCurrentAct->GetUUID(), pValorantAPI);
	m_CurrentActPerformanceID = pCurrentAct->GetUUID();
	m_PeakActPerformanceID = m_CurrentActPerformanceID;
}

CValorantQueuePerformance::CValorantQueuePerformance(
	const std::shared_ptr<const CValorantAPI> pValorantAPI,
	const ValorantQueueType_t QueueType,
	const _APIQueueSkillsTy& APIQueueSkills
) : m_QueueType(QueueType) {

	m_CurrentActPerformanceID = UUID_t::InvalidID();
	m_PeakActPerformanceID = UUID_t::InvalidID();

	ValorantRank_t PeakRank = pValorantAPI->GetUnrankedRank();
	using _SeasonalInfoPairTy = std::pair<const UUID_t, _APIQueueSkillsTy::SeasonalInfoBySeasonID_t>;
	for (const _SeasonalInfoPairTy& SeasonalInfoPair : APIQueueSkills.SeasonalInfoBySeasonID) {
		const std::pair<std::map<UUID_t, CValorantActPerformance>::iterator, bool>& ActPlayerRankEmplaceValue = m_ActPerformances.emplace(
			SeasonalInfoPair.first,
			CValorantActPerformance(pValorantAPI, SeasonalInfoPair.second)
		);

		std::map<UUID_t, CValorantActPerformance>::iterator ActPerformanceIt = ActPlayerRankEmplaceValue.first;
		CValorantActPerformance& ActPerformance = ActPerformanceIt->second;

		std::shared_ptr<const IValorantAct> pAct = ActPerformance.GetAct();
		if (pAct->IsActive()) {
			m_CurrentActPerformanceID = SeasonalInfoPair.first;
		}

		if (ActPerformance.GetPeakRank() >= PeakRank) {
			m_PeakActPerformanceID = SeasonalInfoPair.first;
			PeakRank = ActPerformance.GetPeakRank();
		}
	}

	if (!m_CurrentActPerformanceID.IsValid()) {
		std::shared_ptr<const IValorantAct> pCurrentAct = pValorantAPI->GetCurrentAct();
		m_ActPerformances.emplace(pCurrentAct->GetUUID(), pValorantAPI);
		m_CurrentActPerformanceID = pCurrentAct->GetUUID();

		if (!m_PeakActPerformanceID.IsValid()) {
			m_PeakActPerformanceID = m_CurrentActPerformanceID;
		}
	}
}

ValorantQueueType_t CValorantQueuePerformance::GetQueueType() const {
	return m_QueueType;
}

inline CValorantActPerformance* CValorantQueuePerformance::GetActPerformance(const UUID_t& ActID) {
	using _IteratorType = std::map<UUID_t, CValorantActPerformance>::iterator;

	_IteratorType ActPerformanceIt = m_ActPerformances.find(ActID);

	// couldn't find the act performance with the Act ID
	if (ActPerformanceIt == m_ActPerformances.cend())
		return nullptr;

	return &ActPerformanceIt->second;
}

const IValorantActPerformance* CValorantQueuePerformance::GetActPerformance(const UUID_t& ActID) const {
	using _IteratorType = std::map<UUID_t, CValorantActPerformance>::const_iterator;

	_IteratorType ActPerformanceIt = m_ActPerformances.find(ActID);

	// couldn't find the act performance with the Act ID
	if (ActPerformanceIt == m_ActPerformances.cend())
		return nullptr;

	return &ActPerformanceIt->second;
}

inline CValorantActPerformance* CValorantQueuePerformance::GetActPerformance(const std::shared_ptr<const IValorantAct> pAct) {
	return GetActPerformance(pAct->GetUUID());
}

const IValorantActPerformance* CValorantQueuePerformance::GetActPerformance(const std::shared_ptr<const IValorantAct> pAct) const {
	return GetActPerformance(pAct->GetUUID());
}

inline CValorantActPerformance& CValorantQueuePerformance::GetCurrentActPerformance() {
	return *GetActPerformance(m_CurrentActPerformanceID);
}

const IValorantActPerformance& CValorantQueuePerformance::GetCurrentActPerformance() const {
	return *GetActPerformance(m_CurrentActPerformanceID);
}

inline CValorantActPerformance& CValorantQueuePerformance::GetPeakActPerformance() {
	return *GetActPerformance(m_PeakActPerformanceID);
}

const IValorantActPerformance& CValorantQueuePerformance::GetPeakActPerformance() const {
	return *GetActPerformance(m_PeakActPerformanceID);
}

///////////////////////////////////////////////////
// CValorantPlayer
///////////////////////////////////////////////////
// 
// only used when getting the current match and current pre game
CValorantPlayer::CValorantPlayer(
	const std::shared_ptr<const CValorantAPI> pValorantAPI,
	const UUID_t PlayerID,
	const RiotID_t RiotID,
	const bool bIncognito,
	const std::uint64_t AccountLevel,
	const bool bHideAccountLevel
) : m_pValorantAPI(pValorantAPI), m_PlayerID(PlayerID), m_RiotID(RiotID) {
	m_bLocalPlayer = PlayerID == pValorantAPI->GetLocalPlayerUUID();
	m_bIncognito = bIncognito;
	m_AccountLevel = AccountLevel;
	m_bHideAccountLevel = bHideAccountLevel;
	UpdatePlayerMMR();
}

// shouldn't be used when you have a current match or a pre game
CValorantPlayer::CValorantPlayer(
	const std::shared_ptr<const CValorantAPI> pValorantAPI,
	const UUID_t PlayerID
) : m_pValorantAPI(pValorantAPI), m_PlayerID(PlayerID) {

	m_bLocalPlayer = PlayerID == pValorantAPI->GetLocalPlayerUUID();
	RiotAPIStructure::NameServiceResponse_t Name;
	if (GetValorantAPI()->GetNameFromPlayerUUID(PlayerID, Name)) {
		m_RiotID = Name.GetRiotID();
	}

	if (PlayerID == pValorantAPI->GetLocalPlayerUUID()) {
		// update incognito and hide account level variables
		RiotAPIStructure::PlayerLoadout_t PlayerLoadout;
		if (GetValorantAPI()->GetPlayerLoadout(m_PlayerID, PlayerLoadout)) {
			m_bIncognito = PlayerLoadout.Incognito;
			m_bHideAccountLevel = PlayerLoadout.Identity.HideAccountLevel;
		}
		else {
			m_bIncognito = true;
			m_bHideAccountLevel = true;
		}

		// Update Player Account Level
		RiotAPIStructure::AccountXP_t AccountXP;
		if (GetValorantAPI()->GetAccountXP(m_PlayerID, AccountXP)) {
			m_AccountLevel = AccountXP.Progress.Level;
		}
		else {
			m_AccountLevel = 0;
		}
	}

	UpdatePlayerMMR();
}

const UUID_t& CValorantPlayer::GetPlayerID() const {
	return m_PlayerID;
}

const RiotID_t& CValorantPlayer::GetRiotID() const {
	return m_RiotID;
}

std::uint64_t CValorantPlayer::GetAccountLevel() const {
	return m_AccountLevel;
}

bool CValorantPlayer::IsLocalPlayer() const {
	return m_bLocalPlayer;
}

// streamer mode / hidden name on valorant
bool CValorantPlayer::IsIncognito() const {
	return m_bIncognito;
}

// hidden account level
bool CValorantPlayer::IsHidingAccountLevel() const {
	return m_bHideAccountLevel;
}

// hidden ranked badge
bool CValorantPlayer::IsActBadgeHidden() const {
	return m_bActRankBadgeHidden;
}

// hidden name on Immortal/Radiant leaderboard
bool CValorantPlayer::IsLeaderboardAnonymized() const {
	return m_bLeaderboardAnonymized;
}

inline CValorantQueuePerformance& CValorantPlayer::GetQueuePerformance(const ValorantQueueType_t QueueType) {
	using _QueueTypeIt = std::map<ValorantQueueType_t, CValorantQueuePerformance>::iterator;

	_QueueTypeIt QueueSkillsIt = m_QueuePerformance.find(QueueType);
	if (QueueSkillsIt == m_QueuePerformance.end())
		throw std::invalid_argument("Invalid QueueType");

	return QueueSkillsIt->second;
}

const IValorantQueuePerformance& CValorantPlayer::GetQueuePerformance(const ValorantQueueType_t QueueType) const {
	using _QueueTypeIt = std::map<ValorantQueueType_t, CValorantQueuePerformance>::const_iterator;

	_QueueTypeIt QueueSkillsIt = m_QueuePerformance.find(QueueType);

	if (QueueSkillsIt == m_QueuePerformance.cend())
		throw std::invalid_argument("Invalid QueueType");

	return QueueSkillsIt->second;
}

const IValorantActPerformance& CValorantPlayer::GetCurrentCompetitivePerformance() const {
	return GetQueuePerformance(ValorantQueueType_t::Competitive).GetCurrentActPerformance();
}

const IValorantActPerformance& CValorantPlayer::GetPeakCompetitivePerformance() const {
	return GetQueuePerformance(ValorantQueueType_t::Competitive).GetPeakActPerformance();
}

UUID_t CValorantPlayer::GetAgentSelectID() const {
	RiotAPIStructure::PreGamePlayer_t PreGamePlayer;
	if (!GetValorantAPI()->GetPreGamePlayer(this->GetPlayerID(), PreGamePlayer))
		return UUID_t::InvalidID();

	return PreGamePlayer.m_MatchID;
}

UUID_t CValorantPlayer::GetMatchID() const {
	RiotAPIStructure::CurrentGamePlayer_t CurrentGamePlayer;

	if (!GetValorantAPI()->GetCurrentGamePlayer(this->GetPlayerID(), CurrentGamePlayer))
		return UUID_t::InvalidID();

	return CurrentGamePlayer.m_MatchID;
}

std::shared_ptr<IValorantAgentSelect> CValorantPlayer::GetAgentSelect() const {
	return std::make_shared<CValorantAgentSelect>(GetValorantAPI(), GetAgentSelectID());
}

std::shared_ptr<IValorantMatch> CValorantPlayer::GetMatch() const {
	return std::make_shared<CValorantMatch>(GetValorantAPI(), GetMatchID());
}

void CValorantPlayer::UpdatePlayerMMR() {
	using _PlayerMMRTy = RiotAPIStructure::PlayerMMR_t;
	using _QueueSkillsTy = _PlayerMMRTy::QueueSkills_t;
	using _QueueSkillsIteratorTy = std::map<ValorantQueueType_t, _QueueSkillsTy>::iterator;

	m_bActRankBadgeHidden = true;
	m_bLeaderboardAnonymized = true;
	m_QueuePerformance.clear();

	_PlayerMMRTy PlayerMMR;
	GetValorantAPI()->GetPlayerMMR(m_PlayerID, PlayerMMR);
	auto AddQueuePerformance = [this, &PlayerMMR](const ValorantQueueType_t QueueType) -> void {
		_QueueSkillsIteratorTy APIQueueSkillsIt = PlayerMMR.QueueSkills.find(QueueType);

		// They haven't played this queue Type, so add an empty queue performance
		if (APIQueueSkillsIt == PlayerMMR.QueueSkills.end()) {
			m_QueuePerformance.emplace(
				QueueType,
				CValorantQueuePerformance(
					GetValorantAPI(),
					QueueType
				)
			);
		}
		else {
			const _QueueSkillsTy& QueueSkills = APIQueueSkillsIt->second;

			m_QueuePerformance.emplace(
				QueueType,
				CValorantQueuePerformance(
					GetValorantAPI(),
					QueueType,
					QueueSkills
				)
			);
		}
		};

	AddQueuePerformance(ValorantQueueType_t::Unrated);
	AddQueuePerformance(ValorantQueueType_t::Competitive);
	AddQueuePerformance(ValorantQueueType_t::Swiftplay);
	AddQueuePerformance(ValorantQueueType_t::SpikeRush);
	AddQueuePerformance(ValorantQueueType_t::Deathmatch);
	AddQueuePerformance(ValorantQueueType_t::TeamDeathmatch);
	AddQueuePerformance(ValorantQueueType_t::Premier);
}

///////////////////////////////////////////////////
// CValorantMatchPlayer
///////////////////////////////////////////////////

CValorantMatchPlayer::CValorantMatchPlayer(
	const std::shared_ptr<const CValorantAPI> pValorantAPI,
	const UUID_t& PlayerID,
	const RiotID_t RiotID,
	const bool bIncognito,
	const std::uint64_t AccountLevel,
	const bool bHideAccountLevel,
	const UUID_t& AgentID,
	const TeamID_t Team
) : CValorantPlayer(
	pValorantAPI,
	PlayerID,
	RiotID,
	bIncognito,
	AccountLevel,
	bHideAccountLevel
),
m_pAgent(pValorantAPI->FindAgentWithUUID(AgentID)),
m_Team(Team) {}

bool CValorantMatchPlayer::HasAgent() const {
	return m_pAgent->GetUUID().IsValid();
}

std::shared_ptr<const IValorantAgent> CValorantMatchPlayer::GetAgent() const {
	return m_pAgent;
}

TeamID_t CValorantMatchPlayer::GetTeam() const {
	return m_Team;
}

Color32_t CValorantMatchPlayer::GetTeamColor() const {
	switch (m_Team)
	{
	case TeamID_t::Attacker:
		return Color32_t(255, 120, 120, 255);
		break;
	case TeamID_t::Defender:
		return Color32_t(120, 120, 255, 255);
		break;
	default:
		return Color32_t(255, 255, 255, 255);
		break;
	}
}

///////////////////////////////////////////////////
// CValorantAgentSelect
///////////////////////////////////////////////////

CValorantAgentSelect::CValorantAgentSelect(
	const std::shared_ptr<const CValorantAPI> pValorantAPI,
	const UUID_t& MatchID
) {

	RiotAPIStructure::PreGameMatch_t APIPreGameMatch;

	// class is no longer usable
	if (!pValorantAPI->GetPreGameMatch(MatchID, APIPreGameMatch)) {
		m_MatchID = UUID_t::InvalidID();
		return;
	}

	m_MatchID = APIPreGameMatch.m_MatchID;
	m_Team = APIPreGameMatch.m_AllyTeam.m_TeamID;
	m_pMap = pValorantAPI->FindMapWithURL(APIPreGameMatch.m_MapID);

	std::map<UUID_t, RiotAPIStructure::NameServiceResponse_t> Names;
	std::vector<UUID_t> PlayerUUIDs;
	std::for_each(
		APIPreGameMatch.m_AllyTeam.m_Players.begin(),
		APIPreGameMatch.m_AllyTeam.m_Players.end(),
		[&PlayerUUIDs](const auto& Player) -> void {
			PlayerUUIDs.emplace_back(Player.m_Identity.Subject);
		}
	);

	RiotID_t InvalidRiotID("", "");
	Names = pValorantAPI->GetNamesFromPlayerUUIDList(PlayerUUIDs);
	for (auto& Player : APIPreGameMatch.m_AllyTeam.m_Players) {
		const auto& NameIt = Names.find(Player.m_Identity.Subject);
		const RiotID_t& PlayerName = NameIt != Names.cend() ? NameIt->second.GetRiotID() : InvalidRiotID;

		// use other constructor for player
		m_Teammates.emplace_back(
			pValorantAPI,
			Player.m_Identity.Subject,
			PlayerName,
			Player.m_Identity.Incognito,
			Player.m_Identity.AccountLevel,
			Player.m_Identity.HideAccountLevel,
			Player.m_CharacterID,
			m_Team
		);
	}
}

bool CValorantAgentSelect::IsValid() const {
	return m_MatchID.IsValid();
}

TeamID_t CValorantAgentSelect::GetTeam() const {
	return m_Team;
}

std::vector<const IValorantMatchPlayer*> CValorantAgentSelect::GetTeammates() const {
	std::vector<const IValorantMatchPlayer*> Teammates;

	for (auto& Teammate : m_Teammates)
		Teammates.emplace_back(&Teammate);

	return Teammates;
}

std::shared_ptr<const IValorantMap> CValorantAgentSelect::GetMap() const {
	return m_pMap;
}


///////////////////////////////////////////////////
// CValorantMatch
///////////////////////////////////////////////////

CValorantMatch::CValorantMatch(
	const std::shared_ptr<const CValorantAPI> pValorantAPI,
	const UUID_t& MatchID
) {
	RiotAPIStructure::CurrentGameMatch_t APICurrentGameMatch;

	// class is no longer usable
	if (!pValorantAPI->GetCurrentGameMatch(MatchID, APICurrentGameMatch)) {
		m_MatchID = UUID_t::InvalidID();
		return;
	}

	m_MatchID = APICurrentGameMatch.m_MatchID;
	m_pMap = pValorantAPI->FindMapWithURL(APICurrentGameMatch.m_MapID);

	std::map<UUID_t, RiotAPIStructure::NameServiceResponse_t> Names;
	std::vector<UUID_t> PlayerUUIDs;
	std::for_each(
		APICurrentGameMatch.m_Players.begin(),
		APICurrentGameMatch.m_Players.end(),
		[&PlayerUUIDs](const auto& Player) -> void {
			PlayerUUIDs.emplace_back(Player.m_Identity.Subject);
		}
	);

	Names = pValorantAPI->GetNamesFromPlayerUUIDList(PlayerUUIDs);
	for (auto& Player : APICurrentGameMatch.m_Players) {
		const auto& NameIt = Names.find(Player.m_Identity.Subject);

		m_Players.emplace_back(
			pValorantAPI,
			Player.m_Identity.Subject,
			NameIt != Names.cend() ? NameIt->second.GetRiotID() : RiotID_t(),
			Player.m_Identity.Incognito,
			Player.m_Identity.AccountLevel,
			Player.m_Identity.HideAccountLevel,
			Player.m_CharacterID,
			Player.m_TeamID
		);
	}
}

bool CValorantMatch::IsValid() const {
	return m_MatchID.IsValid();
}

std::shared_ptr<const IValorantMap> CValorantMatch::GetMap() const {
	return m_pMap;
}

std::vector<const IValorantMatchPlayer*> CValorantMatch::GetAttackers() const {
	std::vector<const IValorantMatchPlayer*> Attackers;

	for (const CValorantMatchPlayer& Player : m_Players)
		if (Player.GetTeam() == TeamID_t::Attacker)
			Attackers.emplace_back(&Player);

	return Attackers;
}

std::vector<const IValorantMatchPlayer*> CValorantMatch::GetDefenders() const {
	std::vector<const IValorantMatchPlayer*> Defenders;

	for (const CValorantMatchPlayer& Player : m_Players)
		if (Player.GetTeam() == TeamID_t::Defender)
			Defenders.emplace_back(&Player);

	return Defenders;
}

std::vector<const IValorantMatchPlayer*> CValorantMatch::GetOtherPlayers() const {
	std::vector<const IValorantMatchPlayer*> OtherPlayers;

	for (const CValorantMatchPlayer& Player : m_Players)
		if (Player.GetTeam() == TeamID_t::None)
			OtherPlayers.emplace_back(&Player);

	return OtherPlayers;
}

///////////////////////////////////////////////////
// CValorantAPI
///////////////////////////////////////////////////

CValorantAPI::CValorantAPI() :
	m_pUnofficialAPIEndpoint(std::make_shared<CUnofficialValorantAPI>())
{
	CUnofficialValorantAPI UnofficialAPI;

	m_pInvalidAgent = std::make_shared<CValorantAgent>(
		UUID_t::InvalidID(),
		"",
		Color32_t(255, 255, 255, 255)
	);

	std::map<UUID_t, UnofficialAPIStructures::Agent_t> Agents = UnofficialAPI.GetAgents();
	for (auto& AgentPair : Agents) {
		m_Agents.emplace(
			AgentPair.second.UUID,
			std::make_shared<CValorantAgent>(
				AgentPair.second.UUID,
				AgentPair.second.DisplayName,
				AgentPair.second.BackgroundGradientColors[1]
			)
		);
	}

	m_pInvalidMap = std::make_shared<CValorantMap>("", "");

	std::map<MapURL, UnofficialAPIStructures::Map_t> Maps = UnofficialAPI.GetMaps();
	for (auto& MapPair : Maps) {
		m_Maps.emplace(
			MapPair.second.MapUrl,
			std::make_shared<CValorantMap>(
				MapPair.second.MapUrl,
				MapPair.second.DisplayName
			)
		);
	}

	std::map<UUID_t, UnofficialAPIStructures::CompetitiveTier_t> CompetitiveTiers = UnofficialAPI.GetCompetitiveTiers();

	std::map<
		UUID_t, // Competitive Tier UUID
		std::map<TierID, ValorantRank_t>
	> RanksByUUID;

	static const std::map<std::string, ValorantRank_t::Rank_t> DivisionToRank = {
		{ "Unranked", ValorantRank_t::Rank_t::Unranked },
		{ "Iron", ValorantRank_t::Rank_t::Iron },
		{ "Bronze", ValorantRank_t::Rank_t::Bronze },
		{ "Silver", ValorantRank_t::Rank_t::Silver },
		{ "Gold", ValorantRank_t::Rank_t::Gold },
		{ "Platinum", ValorantRank_t::Rank_t::Platinum },
		{ "Diamond", ValorantRank_t::Rank_t::Diamond },
		{ "Ascendant", ValorantRank_t::Rank_t::Ascendant },
		{ "Immortal", ValorantRank_t::Rank_t::Immortal },
		{ "Radiant", ValorantRank_t::Rank_t::Radiant }
	};

	for (const std::pair<const UUID_t, UnofficialAPIStructures::CompetitiveTier_t>& CompTierPair : CompetitiveTiers) {
		std::map<TierID, ValorantRank_t> Ranks;

		for (const UnofficialAPIStructures::CompetitiveTier_t::Tier_t& Tier : CompTierPair.second.Tiers) {
			std::map<std::string, ValorantRank_t::Rank_t>::const_iterator ValorantRankIt = DivisionToRank.find(Tier.DivisionName);
			ValorantRank_t::Rank_t ValorantRank = ValorantRank_t::Rank_t::Unknown;
			std::string TierName = "Unknown";
			std::uint8_t Division = ValorantRank_t::DivisionNone;
			if (ValorantRankIt != DivisionToRank.cend()) {
				TierName = Tier.DivisionName;
				ValorantRank = ValorantRankIt->second;

				std::regex DivisonNumberExpression("\\d+");
				auto DivisionNumber = std::sregex_iterator(
					Tier.TierName.begin(),
					Tier.TierName.end(),
					DivisonNumberExpression
				);

				if (DivisionNumber != std::sregex_iterator()) {
					Division = static_cast<std::uint8_t>(std::stoul(DivisionNumber->str()));
				}
			}

			TierID InternalTierID = Tier.Tier;
			Color32_t RankColor = Tier.Color;

			Ranks.emplace(
				InternalTierID,
				ValorantRank_t(
					ValorantRank,
					TierName,
					Division,
					RankColor
				)
			);
		}

		RanksByUUID.emplace(CompTierPair.second.UUID, Ranks);
	}

	// key season UUID
	std::map<UUID_t, UnofficialAPIStructures::CompetitiveSeason_t> CompetitiveSeasons = UnofficialAPI.GetCompetitiveSeasons();
	std::map<UUID_t, UnofficialAPIStructures::Season_t> Seasons = UnofficialAPI.GetSeasons();

	using _SeasonPairTy = const std::pair<const UUID_t, UnofficialAPIStructures::Season_t>;
	using _SeasonValueTy = UnofficialAPIStructures::Season_t;

	std::vector<_SeasonValueTy> RawEpisodes;
	std::vector<_SeasonValueTy> RawActs;

	std::for_each(
		Seasons.begin(),
		Seasons.end(),
		[&RawEpisodes, &RawActs](const _SeasonPairTy& SeasonPair) -> void {
			const _SeasonValueTy& Season = SeasonPair.second;

			// Check if it's an episode by checking the parent UUID.
			// Only acts contain a parent UUID and an Episodes' parent 
			// UUID is invalid
			if (Season.ParentUUID.IsValid()) {
				RawActs.emplace_back(Season);
			}
			else {
				RawEpisodes.emplace_back(Season);
			}
		}
	);

	for (_SeasonValueTy& RawEpisode : RawEpisodes) {
		using _CompSeasonIteratorTy = std::map<UUID_t, UnofficialAPIStructures::CompetitiveSeason_t>::const_iterator;
		using _CompSeasonTy = UnofficialAPIStructures::CompetitiveSeason_t;
		_CompSeasonIteratorTy RawCompSeasonIt = CompetitiveSeasons.find(RawEpisode.UUID);
		if (RawCompSeasonIt == CompetitiveSeasons.cend())
			continue; // couldn't find a comp season with the sseason uuid

		const _CompSeasonTy& RawCompSeason = RawCompSeasonIt->second;

		using _CompRanksIteratorTy = std::map<
			UUID_t,
			std::map<TierID, ValorantRank_t>
		>::iterator;
		using _CompRanksTy = std::map<TierID, ValorantRank_t>;

		_CompRanksIteratorTy RawCompRanksIt = RanksByUUID.find(RawCompSeason.CompetitiveTeirUUID);
		if (RawCompRanksIt == RanksByUUID.cend())
			continue; // couldn't find the ranks associated with this episode

		_CompRanksTy& RawCompetitiveRanks = RawCompRanksIt->second;
		// children of the episode
		std::vector<_SeasonValueTy> EpisodeRawActs;

		// add all children. Not the best way to do this but whatever we
		// only do it once who cares
		std::for_each(
			RawActs.begin(),
			RawActs.end(),
			[&EpisodeRawActs, &RawEpisode](const _SeasonValueTy& Act) -> void {
				if (Act.ParentUUID == RawEpisode.UUID)
					EpisodeRawActs.emplace_back(Act);
			}
		);

		std::shared_ptr<CValorantEpisode> pEpisode = std::make_shared<CValorantEpisode>(
			RawEpisode.UUID,
			RawCompetitiveRanks,
			RawEpisode.EpisodeNr,
			RawEpisode.StartTime,
			RawEpisode.EndTime
		);

		if (RawEpisode.IsBeta) {
			pEpisode->AddActs({ RawEpisode });
		}

		pEpisode->AddActs(EpisodeRawActs);

		m_Episodes.emplace(pEpisode->GetUUID(), pEpisode);

		const std::vector<std::shared_ptr<CValorantAct>>& EpisodeActs = pEpisode->GetActs();

		std::for_each(
			EpisodeActs.begin(),
			EpisodeActs.end(),
			[this, pEpisode](const std::shared_ptr<CValorantAct>& pAct) -> void {
				m_Acts.emplace(pAct->GetUUID(), pAct);

				if (pAct->IsActive()) {
					m_CurrentAct = pAct;
				}
			}
		);
	}

	m_Unranked = ValorantRank_t(
		ValorantRank_t::Rank_t::Unranked,
		"Unranked",
		ValorantRank_t::DivisionNone,
		Color32_t(255, 255, 255, 255)
	);

	m_PlacementsRank = ValorantRank_t(
		ValorantRank_t::Rank_t::Placements,
		"Placements",
		ValorantRank_t::DivisionNone,
		Color32_t(255, 255, 255, 255)
	);
}

inline std::shared_ptr<const CValorantAgent> CValorantAPI::FindAgentWithUUID(
	const UUID_t& AgentUUID
) const {
	auto AgentIt = m_Agents.find(AgentUUID);

	if (AgentIt == m_Agents.cend())
		return m_pInvalidAgent;

	return AgentIt->second;
}

inline std::shared_ptr<const CValorantMap> CValorantAPI::FindMapWithURL(
	const MapURL& URL
) const {
	auto MapIt = m_Maps.find(URL);

	if (MapIt == m_Maps.cend())
		return m_pInvalidMap;

	return MapIt->second;
}


inline std::shared_ptr<const CValorantAct> CValorantAPI::GetAct(
	const UUID_t& ActID
) const {
	auto ActIt = m_Acts.find(ActID);

	if (ActIt == m_Acts.cend())
		throw std::invalid_argument("Invalid ActID");

	return ActIt->second;
}

inline std::shared_ptr<const CValorantAct> CValorantAPI::GetCurrentAct() const {
	return m_CurrentAct;
}

inline const ValorantRank_t& CValorantAPI::GetUnrankedRank() const {
	return m_Unranked;
}

inline const ValorantRank_t& CValorantAPI::GetPlacementsRank() const {
	return m_PlacementsRank;
}

std::unique_ptr<IValorantPlayer> CValorantAPI::GetPlayer(const UUID_t& PlayerID) {
	return std::make_unique<CValorantPlayer>(shared_from_this(), PlayerID);
}

std::unique_ptr<IValorantPlayer> CValorantAPI::GetLocalPlayer() {
	return GetPlayer(GetLocalPlayerUUID());
}

std::shared_ptr<IValorantAPI> g_pValorantAPI;
std::shared_ptr<IValorantAPI> IValorantAPI::Get() {
	if (g_pValorantAPI)
		return g_pValorantAPI;

	g_pValorantAPI = std::make_shared<CValorantAPI>();
	return g_pValorantAPI;
}

_VALORANT_API_NAMESPACE_END