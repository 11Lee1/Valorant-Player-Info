#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <cassert>
#include <memory>
#include <algorithm>
#include <thread>
#include <vector>
#include <format>
#include <chrono>
#include <iostream>
#include <functional>
#include "riotapi.h"

// ENABLE_VIRTUAL_TERMINAL_PROCESSING must be enabled
inline std::string AddColorToText(
	const std::string& Text,
	const ValorantAPI::Color32_t& Color
) {
	return std::vformat(
		"\x1B[38;2;{};{};{}m{}"
		"\x1B[m", // reset the color after our text
		std::make_format_args(Color.R(), Color.G(), Color.B(), Text)
	);
}

struct PrintableText_t {
	PrintableText_t() :
		Text(""), TextColor(255, 255, 255, 255), TextLength(0) {}
	PrintableText_t(_In_ const std::string _Text, _In_ const ValorantAPI::Color32_t _TextColor) :
		Text(_Text), TextColor(_TextColor), TextLength(_Text.length()) {}

	inline const std::string& GetText() const {
		return Text;
	}

	inline const std::string GetTextForPrinting() const {
		return AddColorToText(Text, TextColor);
	}

	inline std::size_t Length() const { return TextLength; }
	inline const ValorantAPI::Color32_t& GetColor() const { return TextColor; }

	inline PrintableText_t& operator+(const std::string& Str) {
		this->Text += "\x1B[0m" + Str;
		this->TextLength += Str.length();
		return *this;
	}

	inline PrintableText_t& operator+=(const std::string& Str) {
		this->Text += "\x1B[0m" + Str;
		this->TextLength += Str.length();
		return *this;
	}

	inline const PrintableText_t operator+(const std::string& Str) const {
		PrintableText_t _Text;

		_Text.Text = this->Text + "\x1B[0m" + Str;
		_Text.TextLength = this->TextLength + Str.length();
		_Text.TextColor = this->TextColor;
		return _Text;
	}

	inline PrintableText_t& operator+(const PrintableText_t& Str) {
		this->Text += Str.GetTextForPrinting();
		this->TextLength += Str.Length();
		return *this;
	}

	inline const PrintableText_t operator+(const PrintableText_t& Str) const {
		PrintableText_t _Text;

		_Text.Text = this->Text + Str.GetTextForPrinting();
		_Text.TextLength = this->TextLength + Str.Length();
		_Text.TextColor = this->TextColor;
		return _Text;
	}

protected:
	std::string Text;
	std::size_t TextLength;
	ValorantAPI::Color32_t TextColor;
};

class ConsoleTable
{
	static constexpr std::size_t NumHorizontalPaddingBetweenBorder = 1;

public:
	struct Column_t {
		friend class ConsoleTable;
	public:
		Column_t() = delete;
		Column_t(const PrintableText_t& ColumnName) {
			m_ColumnName = ColumnName;
			m_LongestStringLength = ColumnName.Length();
		}
	public:
		void AddRow(const PrintableText_t& Text) {
			this->m_Rows.emplace_back(Text);
			m_LongestStringLength = std::max<std::size_t>(Text.Length(), m_LongestStringLength);
		}

		void AddEmptyRow() {
			const PrintableText_t Empty("", ValorantAPI::Color32_t(0, 0, 0, 0));
			AddRow(Empty);
		}

		inline std::vector<PrintableText_t>::size_type NumRows() const {
			return m_Rows.size();
		}

		inline std::vector<PrintableText_t>::size_type GetLongestStringLength() const {
			return m_LongestStringLength;
		}

		inline std::vector<PrintableText_t>::iterator GetRow(std::vector<PrintableText_t>::size_type Row) {
			if (Row >= m_Rows.size())
				return m_Rows.end();

			return m_Rows.begin() + Row;
		}

		inline std::vector<PrintableText_t>::const_iterator GetRow(std::vector<PrintableText_t>::size_type Row) const {
			if (Row >= m_Rows.size())
				return m_Rows.end();

			return m_Rows.begin() + Row;
		}

		inline const PrintableText_t& GetName() const {
			return m_ColumnName;
		}

		inline PrintableText_t& GetNasme() {
			return m_ColumnName;
		}

		inline std::vector<PrintableText_t>::iterator GetEnd() {
			return m_Rows.end();
		}

		inline std::vector<PrintableText_t>::const_iterator GetEnd() const {
			return m_Rows.cend();
		}

		inline std::vector<PrintableText_t>::iterator GetBegin() {
			return m_Rows.begin();
		}

		inline std::vector<PrintableText_t>::const_iterator GetBegin() const {
			return m_Rows.begin();
		}

		inline void clear() {
			m_LongestStringLength = m_ColumnName.Length();
			m_Rows.clear();
		}
	protected:
		PrintableText_t m_ColumnName;
		std::size_t m_LongestStringLength;
		std::vector<PrintableText_t> m_Rows;
	};
	friend struct Column_t;
public:
	std::vector<std::string> ToConsoleLines() const {
		// how many lines we need for each line in the column name wrapper
		static constexpr std::size_t ColumnNameWrapperNumLines = 3;
		// how many lines we need for the bottom bar
		static constexpr std::size_t BottomBarNumLines = 1;

		// *gag* dunno why but when I do a utf escape sequence as a character
		// pointer it just gives me garbage maybe I'm retarded... 
		// example: static constexpr const char* Whatever = "\u2500"
		// will show up as "?".  I also don't wanna do some template 
		// tomfoolery so oh well gotta use this dumb ugly workaround
		static constexpr const char PaddingCharacter = L' ';
		const char* HorizontalBorderChar = (const char*)u8"\u2500";
		const char* VerticalBorderChar = (const char*)u8"\u2502";
		const char* TopLeftBorderChar = (const char*)u8"\u250C";
		const char* TopRightBorderChar = (const char*)u8"\u2510";
		const char* BottomLeftBorderChar = (const char*)u8"\u2514";
		const char* BottomRightBorderChar = (const char*)u8"\u2518";
		const char* VerticalSeparatorDown = (const char*)u8"\u252C";
		const char* VerticalSeparatorUp = (const char*)u8"\u2534";
		const char* Cross = (const char*)u8"\u253C";
		const char* HorizontalSeparatorRight = (const char*)u8"\u251C";
		const char* HorizontalSeparatorLeft = (const char*)u8"\u2524";

		std::vector<std::string> RetVal;

		std::size_t NumValueRows = NumLongestColumnRows();
		const std::size_t AmountToReserve = NumValueRows +
			ColumnNameWrapperNumLines + BottomBarNumLines;

		const std::size_t ValueRowsBeginIdx = ColumnNameWrapperNumLines;
		const std::size_t ValueRowsEndIdx = ValueRowsBeginIdx + NumValueRows;
		const std::size_t BottomBarIdx = ValueRowsEndIdx;

		RetVal.reserve(AmountToReserve);
		RetVal.insert(RetVal.end(), AmountToReserve, "");

		const std::vector<std::string>::iterator TopBar = RetVal.begin();
		const std::vector<std::string>::iterator ColumnNameBar = RetVal.begin() + 1;
		const std::vector<std::string>::iterator ColumnNameBottomBar = RetVal.begin() + 2;
		const std::vector<std::string>::iterator BottomBar = RetVal.begin() + BottomBarIdx;
		const std::vector<std::string>::iterator ValueRowsBegin = RetVal.begin() + ValueRowsBeginIdx;
		const std::vector<std::string>::iterator ValueRowsEnd = RetVal.begin() + ValueRowsEndIdx;

		for (
			std::vector<Column_t>::const_iterator ColumnIt = m_Columns.cbegin();
			ColumnIt != m_Columns.cend();
			ColumnIt++
			) {
			const bool IsFirst = ColumnIt == m_Columns.cbegin();
			const bool IsLast = std::next(ColumnIt) == m_Columns.cend();
			const PrintableText_t& ColumnName = ColumnIt->GetName();
			const std::size_t ColumnNameLength = ColumnName.Length();
			const std::size_t ColumnLongestStringLength = ColumnIt->GetLongestStringLength();

			ColumnNameBar->append(VerticalBorderChar);
			ColumnNameBar->append(NumHorizontalPaddingBetweenBorder, PaddingCharacter);
			ColumnNameBar->append(ColumnName.GetTextForPrinting());
			ColumnNameBar->append(NumHorizontalPaddingBetweenBorder + ColumnLongestStringLength - ColumnNameLength, PaddingCharacter);

			// Top bar
			TopBar->append(
				IsFirst ? TopLeftBorderChar : VerticalSeparatorDown
			);

			// Column bottom
			ColumnNameBottomBar->append(
				IsFirst ? HorizontalSeparatorRight : Cross
			);

			// bottom bar
			BottomBar->append(
				IsFirst ? BottomLeftBorderChar : VerticalSeparatorUp
			);

			for (std::size_t i = 0; i < 2 * NumHorizontalPaddingBetweenBorder + ColumnLongestStringLength; i++) {
				TopBar->append(HorizontalBorderChar);
				ColumnNameBottomBar->append(HorizontalBorderChar);
				BottomBar->append(HorizontalBorderChar);
			}

			if (IsLast) {
				ColumnNameBar->append(
					VerticalBorderChar
				);
				TopBar->append(
					TopRightBorderChar
				);
				ColumnNameBottomBar->append(
					HorizontalSeparatorLeft
				);
				BottomBar->append(
					BottomRightBorderChar
				);
			}

			std::size_t RowNr = 0;
			for (std::vector<std::string>::iterator CurRowIt = ValueRowsBegin;
				CurRowIt != ValueRowsEnd;
				CurRowIt++, RowNr++) {

				CurRowIt->append(
					VerticalBorderChar
				);
				CurRowIt->append(NumHorizontalPaddingBetweenBorder, PaddingCharacter);

				std::vector<PrintableText_t>::const_iterator CurColumnRowValueIt = ColumnIt->GetRow(RowNr);
				if (CurColumnRowValueIt != ColumnIt->GetEnd()) {
					CurRowIt->append(CurColumnRowValueIt->GetTextForPrinting());
					CurRowIt->append(NumHorizontalPaddingBetweenBorder +
						ColumnLongestStringLength - CurColumnRowValueIt->Length(),
						PaddingCharacter
					);
				}
				else {
					CurRowIt->append(
						NumHorizontalPaddingBetweenBorder + ColumnLongestStringLength,
						PaddingCharacter
					);
				}

				if (IsLast)
					CurRowIt->append(
						VerticalBorderChar
					);
			}
		}
		return RetVal;
	}

	using ColumnID = std::vector<Column_t>::size_type;

	ColumnID AddColumn(const PrintableText_t& ColumnName) {
		m_Columns.emplace_back(ColumnName);
		return m_Columns.size() - 1;
	}

	Column_t& GetColumn(const ColumnID ID) {
		assert(m_Columns.size() > ID);

		return m_Columns.at(ID);
	}

	const Column_t& GetColumn(const ColumnID ID) const {
		assert(m_Columns.size() > ID);

		return m_Columns.at(ID);
	}

	const std::vector<Column_t>::size_type NumLongestColumnRows() const {
		std::vector<Column_t>::size_type Length = 0;

		std::for_each(
			m_Columns.begin(),
			m_Columns.end(),
			[&Length](const Column_t& Column) {
				Length = std::max<std::vector<Column_t>::size_type>(Column.NumRows(), Length);
			}
		);

		return Length;
	}

	void ClearColumns() {
		for (auto& Column : m_Columns) {
			Column.clear();
		}
	}

private:
	std::vector<Column_t> m_Columns;
};

class CGameConsoleTable : public ConsoleTable
{
public:
	CGameConsoleTable() {
		m_AgentTableID = AddColumn(
			PrintableText_t("Agent", ValorantAPI::Color32_t(255, 255, 255, 255))
		);

		m_RiotIDID = AddColumn(
			PrintableText_t("RiotID", ValorantAPI::Color32_t(255, 255, 255, 255))
		);

		m_RanksID = AddColumn(
			PrintableText_t("Rank", ValorantAPI::Color32_t(255, 255, 255, 255))
		);

		m_PeakRankID = AddColumn(
			PrintableText_t("Peak Rank", ValorantAPI::Color32_t(255, 255, 255, 255))
		);

		m_WinRateID = AddColumn(
			PrintableText_t("W/L/G - %", ValorantAPI::Color32_t(255, 255, 255, 255))
		);
	}

	void AddSpacer() {
		ConsoleTable::Column_t& Agents = GetColumn(m_AgentTableID);
		ConsoleTable::Column_t& RiotIDs = GetColumn(m_RiotIDID);
		ConsoleTable::Column_t& Ranks = GetColumn(m_RanksID);
		ConsoleTable::Column_t& PeakRanks = GetColumn(m_PeakRankID);
		ConsoleTable::Column_t& WinRate = GetColumn(m_WinRateID);

		Agents.AddEmptyRow();
		RiotIDs.AddEmptyRow();
		Ranks.AddEmptyRow();
		PeakRanks.AddEmptyRow();
		WinRate.AddEmptyRow();
	}

	void AddPlayer(const ValorantAPI::IValorantMatchPlayer* pPlayer) {
		ConsoleTable::Column_t& Agents = GetColumn(m_AgentTableID);
		ConsoleTable::Column_t& RiotIDs = GetColumn(m_RiotIDID);
		ConsoleTable::Column_t& CurrentRanks = GetColumn(m_RanksID);
		ConsoleTable::Column_t& PeakRanks = GetColumn(m_PeakRankID);
		ConsoleTable::Column_t& WinRate = GetColumn(m_WinRateID);

		const ValorantAPI::IValorantActPerformance& CurrentActPerformance = pPlayer->GetCurrentCompetitivePerformance();
		const ValorantAPI::IValorantActPerformance& PeakActPerformance = pPlayer->GetPeakCompetitivePerformance();
		const ValorantAPI::ValorantRank_t& CurrentRank = CurrentActPerformance.GetRank();

		std::shared_ptr<const ValorantAPI::IValorantAgent> pAgent = pPlayer->GetAgent();

		Agents.AddRow(
			PrintableText_t(
				pAgent->GetName(),
				pAgent->GetColor()
			)
		);

		const ValorantAPI::RiotID_t& RiotID = pPlayer->GetRiotID();
		RiotIDs.AddRow(
			PrintableText_t(
				RiotID.GetFormatted(), //SanitizeUTF8StringForPrinting(RiotID.GetFormatted()),
				pPlayer->GetTeamColor()
			)
		);

		PrintableText_t CurrentRankText(
			CurrentRank.GetFullName(),
			CurrentRank.GetRankColor()
		);

		std::uint64_t nGames = CurrentActPerformance.GetNumGames();
		std::uint64_t nWins = CurrentActPerformance.GetWins();
		std::uint64_t nLosses = CurrentActPerformance.GetLosses();

		if (nGames) {
			CurrentRankText += " (" + std::to_string(CurrentActPerformance.GetRankedRating()) + ")";

			PrintableText_t CurrentRankedWins(std::to_string(nWins), ValorantAPI::Color32_t(0, 255, 0, 255));
			PrintableText_t CurrentRankedLosses(std::to_string(nLosses), ValorantAPI::Color32_t(255, 0, 0, 255));

			PrintableText_t RankedWinRateStats = CurrentRankedWins + "/" +
				CurrentRankedLosses + "/" +
				std::to_string(nGames) + " - " +
				std::vformat("{:.2f}", std::make_format_args(CurrentActPerformance.GetWinProbability() * 100.f));

			WinRate.AddRow(RankedWinRateStats);
		}
		else {
			WinRate.AddEmptyRow();
		}

		CurrentRanks.AddRow(CurrentRankText);

		if (PeakActPerformance.IsRanked()) {
			const ValorantAPI::ValorantRank_t& PeakRank = PeakActPerformance.GetPeakRank();

			std::shared_ptr<const ValorantAPI::IValorantAct> pPeakRankAct = PeakActPerformance.GetAct();

			PrintableText_t PeakRankText(PeakRank.GetFullName(), PeakRank.GetRankColor());
			PeakRankText += std::vformat(
				" (E{}A{})",
				std::make_format_args(
					pPeakRankAct->GetEpisodeNumber(),
					pPeakRankAct->GetActNumber()
				)
			);

			PeakRanks.AddRow(PeakRankText);
		}
		else {
			PeakRanks.AddEmptyRow();
		}
	}
private:
	ConsoleTable::ColumnID m_AgentTableID;
	ConsoleTable::ColumnID m_RiotIDID;
	ConsoleTable::ColumnID m_RanksID;
	ConsoleTable::ColumnID m_PeakRankID;
	ConsoleTable::ColumnID m_WinRateID;
};

void DoAgentSelect(
	CGameConsoleTable& Table,
	std::shared_ptr<const ValorantAPI::IValorantPlayer> pLocalPlayer
) {
	system("cls");
	std::shared_ptr<ValorantAPI::IValorantAgentSelect> pAgentSelect = pLocalPlayer->GetAgentSelect();

	if (!pAgentSelect->IsValid())
		return;

	Table.ClearColumns();

	const std::vector<const ValorantAPI::IValorantMatchPlayer*> Teammates = pAgentSelect->GetTeammates();

	std::for_each(
		Teammates.begin(),
		Teammates.end(),
		std::bind(&CGameConsoleTable::AddPlayer, &Table, std::placeholders::_1)
	);

	std::vector<std::string> ConsoleLines = Table.ToConsoleLines();

	std::for_each(
		ConsoleLines.begin(),
		ConsoleLines.end(),
		[](const std::string& Line) -> void {
			std::cout << Line << std::endl;
		}
	);
}

void DoMatch(
	CGameConsoleTable& Table,
	std::shared_ptr<const ValorantAPI::IValorantPlayer> pLocalPlayer
) {
	system("cls");
	std::shared_ptr<ValorantAPI::IValorantMatch> pMatch = pLocalPlayer->GetMatch();

	if (!pMatch->IsValid())
		return;

	Table.ClearColumns();

	const std::vector<const ValorantAPI::IValorantMatchPlayer*> Attackers = pMatch->GetAttackers();
	const std::vector<const ValorantAPI::IValorantMatchPlayer*> Defenders = pMatch->GetDefenders();

	std::for_each(
		Attackers.begin(),
		Attackers.end(),
		std::bind(&CGameConsoleTable::AddPlayer, &Table, std::placeholders::_1)
	);

	if (Attackers.size())
		Table.AddSpacer();

	std::for_each(
		Defenders.begin(),
		Defenders.end(),
		std::bind(&CGameConsoleTable::AddPlayer, &Table, std::placeholders::_1)
	);

	std::vector<std::string> ConsoleLines = Table.ToConsoleLines();

	std::for_each(
		ConsoleLines.begin(),
		ConsoleLines.end(),
		[](const std::string& Line) -> void {
			std::cout << Line << std::endl;
		}
	);
}

bool g_bRunLoop = false;

BOOL WINAPI ConsoleHandlerRoutine(_In_ DWORD dwCtrlType) {
	switch (dwCtrlType)
	{
	case CTRL_CLOSE_EVENT:
	case CTRL_LOGOFF_EVENT:
	case CTRL_SHUTDOWN_EVENT:
		g_bRunLoop = false;
		break;
	default:
		break;
	}

	return false; // next function in the handler list
}

#ifndef _CONSOLE
int APIENTRY WinMain(
	_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ PSTR CMDLine,
	_In_ int CMDShow
) {
	UNREFERENCED_PARAMETER(hInstance);
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(CMDLine);
	UNREFERENCED_PARAMETER(CMDShow);

	if (!AllocConsole())
		return GetLastError();

	FILE* Temp;
	if (freopen_s(&Temp, "CONOUT$", "w", stdout))
		return GetLastError();
#else
int main() {
#endif
	HANDLE hSTDOut;
	DWORD Mode;

	SetConsoleCP(CP_UTF8);
	SetConsoleOutputCP(CP_UTF8);

	hSTDOut = GetStdHandle(STD_OUTPUT_HANDLE);
	if (hSTDOut == INVALID_HANDLE_VALUE)
		return GetLastError();

	if (!GetConsoleMode(hSTDOut, &Mode))
		return GetLastError();

	Mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
	if (!SetConsoleMode(hSTDOut, Mode))
		return GetLastError();

	if (!SetConsoleCtrlHandler(ConsoleHandlerRoutine, TRUE))
		return GetLastError();

	g_bRunLoop = true;
	CGameConsoleTable Table;
	ValorantAPI::UUID_t CurrentMatchID;
	bool bAgentSelect = false;

	std::shared_ptr<ValorantAPI::IValorantAPI> pValAPI = ValorantAPI::IValorantAPI::Get();
	const std::shared_ptr<const ValorantAPI::IValorantPlayer> pLocalPlayer = pValAPI->GetLocalPlayer();
	while (g_bRunLoop) {
		ValorantAPI::UUID_t NewMatchID = pLocalPlayer->GetAgentSelectID();
		if (NewMatchID.IsValid()) {
			if (NewMatchID != CurrentMatchID) {
				DoAgentSelect(Table, pLocalPlayer);

				CurrentMatchID = NewMatchID;
				bAgentSelect = true;
			}
		}
		else {
			NewMatchID = pLocalPlayer->GetMatchID();
			if (NewMatchID.IsValid() && NewMatchID != CurrentMatchID || bAgentSelect) {
				DoMatch(Table, pLocalPlayer);
				CurrentMatchID = NewMatchID;
				bAgentSelect = false;
			}
		}
		std::this_thread::sleep_for(std::chrono::seconds(5));
	}

	return 0;
}