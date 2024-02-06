#ifndef RIOTAPI_H
#define RIOTAPI_H
#pragma once
#include <memory>
#include <string>
#include <vector>
#include <ctime>

#define _VALORANT_API_NAMESPACE ValorantAPI
#define _VALORANT_API_NAMESPACE_BEGIN namespace _VALORANT_API_NAMESPACE {
#define _VALORANT_API_NAMESPACE_END }

_VALORANT_API_NAMESPACE_BEGIN
struct UUID_t
{
public:
	static constexpr std::string_view szInvalidID = "ffffffff-ffff-ffff-ffff-ffffffffffff";
	static constexpr std::wstring_view szInvalidIDW = L"ffffffff-ffff-ffff-ffff-ffffffffffff";

	UUID_t();
	UUID_t(const std::string_view& ID);

	static UUID_t InvalidID() { return UUID_t(szInvalidID.data()); }

	inline UUID_t& operator=(const std::string& ID) = delete;
	inline UUID_t& operator=(const char* ID) = delete;

	inline bool operator==(const UUID_t& ID) const {
		return this->GetRawID() == ID.GetRawID();
	}

	inline bool operator!=(const UUID_t& ID) const {
		return this->GetRawID() != ID.GetRawID();
	}

	inline bool IsValid() const {
		return m_ID != szInvalidID;
	}

	// so std::map doesn't scream at us
	inline bool operator<(const UUID_t& ID) const {
		return this->GetRawID() < ID.GetRawID();
	}

	// so std::map doesn't scream at us
	inline bool operator>(const UUID_t& ID) const {
		return this->GetRawID() > ID.GetRawID();
	}

	inline const std::string& GetRawID() const { return m_ID; }
	inline const std::wstring GetRawIDW() const { return m_IDW; }
private:
	std::string m_ID;
	std::wstring m_IDW;
};

struct RiotID_t {
	RiotID_t() : m_InGameName(""), m_TagLine(""), m_FormattedName("") {}
	RiotID_t(
		const std::string& InGameName, const std::string& Tagline
	) : m_InGameName(InGameName),
		m_TagLine(Tagline),
		m_FormattedName(InGameName + "#" + Tagline) {}

	inline const std::string& GetFormatted() const { return m_FormattedName; }
	inline const std::string& GetInGameName() const { return m_InGameName; }
	inline const std::string& GetTagLine() const { return m_TagLine; }

private:
	std::string m_InGameName;
	std::string m_TagLine;
	std::string m_FormattedName;
};

struct Color32_t
{
public:
	Color32_t() {
		Color.u8.r = 0;
		Color.u8.g = 0;
		Color.u8.b = 0;
		Color.u8.a = 0;
	}

	Color32_t(
		_In_ const unsigned char _r,
		_In_ const unsigned char _g,
		_In_ const unsigned char _b,
		_In_ const unsigned char _a
	) {
		Set(_r, _g, _b, _a);
	}

	void Set(
		_In_ const unsigned char _r,
		_In_ const unsigned char _g,
		_In_ const unsigned char _b,
		_In_ const unsigned char _a
	) {
		Color.u8.r = _r;
		Color.u8.g = _g;
		Color.u8.b = _b;
		Color.u8.a = _a;
	}

	inline unsigned char R() const { return Color.u8.r; }
	inline unsigned char G() const { return Color.u8.g; }
	inline unsigned char B() const { return Color.u8.b; }
	inline unsigned char A() const { return Color.u8.a; }
	inline unsigned char& R() { return Color.u8.r; }
	inline unsigned char& G() { return Color.u8.g; }
	inline unsigned char& B() { return Color.u8.b; }
	inline unsigned char& A() { return Color.u8.a; }

protected:
	union {
		struct {
			std::uint32_t Col;
		} u32;
		struct {
			std::uint16_t ColHi;
			std::uint16_t ColLo;
		} u16;
		struct {
			std::uint8_t r, g, b, a;
		} u8;
	} Color;
};

class CTime
{
public:
	static CTime Now();
	static CTime NowLocal();

	CTime();
	CTime(const __time64_t UnixTime);
	CTime(const std::tm& Time);
	CTime(const std::wstring& ISOTime);
	CTime(const std::string& ISOTime);
	std::wstring GetISOFormatW() const;
	std::string GetISOFormat() const;
	__time64_t GetUnix() const;
	std::tm GetCTime() const;

	bool operator==(const CTime& Time) const;
	bool operator>(const CTime& Time) const;
	bool operator>=(const CTime& Time) const;
	bool operator<(const CTime& Time) const;
	bool operator<=(const CTime& Time) const;
private:
	__time64_t m_Time;
};

enum class TeamID_t : std::size_t {
	None = -1,
	Attacker = 0,
	Defender = 1
};

enum class ValorantQueueType_t {
	Unknown = -1,
	Unrated,
	Competitive,
	Swiftplay,
	SpikeRush,
	Deathmatch,
	TeamDeathmatch,
	Premier
};

struct ValorantRank_t {
	// used for checking if a player is radiant, episode 1 immortal or whatever
	static constexpr std::uint16_t DivisionNone = 0;

	enum class Rank_t : std::uint16_t {
		Unknown,
		Unranked,
		Placements,
		Iron,
		Bronze,
		Silver,
		Gold,
		Platinum,
		Diamond,
		Ascendant,
		Immortal,
		Radiant
	};

	ValorantRank_t();
	ValorantRank_t(
		Rank_t Rank,
		std::string TierName,
		std::uint8_t Division,
		Color32_t RankColor
	);

	inline bool operator==(const ValorantRank_t& CmpRank) const {
		return this->m_Rank == CmpRank.m_Rank && this->m_Division == CmpRank.m_Division;
	}

	inline bool operator!=(const ValorantRank_t& CmpRank) const {
		return this->m_Rank != CmpRank.m_Rank || this->m_Division != CmpRank.m_Division;
	}

	inline bool operator>(const ValorantRank_t& CmpRank) const {
		[[unlikely]] if (this->m_Rank == CmpRank.m_Rank)
			return this->m_Division > CmpRank.m_Division;

		return this->m_Rank > CmpRank.m_Rank;
	}

	inline bool operator<(const ValorantRank_t& CmpRank) const {
		[[unlikely]] if (this->m_Rank == CmpRank.m_Rank)
			return this->m_Division < CmpRank.m_Division;

		return this->m_Rank < CmpRank.m_Rank;
	}

	inline bool operator>=(const ValorantRank_t& CmpRank) const {
		[[unlikely]] if (this->m_Rank == CmpRank.m_Rank)
			return this->m_Division >= CmpRank.m_Division;

		return this->m_Rank > CmpRank.m_Rank;
	}

	inline bool operator<=(const ValorantRank_t& CmpRank) const {
		[[unlikely]] if (this->m_Rank == CmpRank.m_Rank)
			return this->m_Division >= CmpRank.m_Division;

		return this->m_Rank < CmpRank.m_Rank;
	}

	inline const std::string& GetTierName() const { return m_TierName; }
	inline const std::string& GetFullName() const { return m_FullName; }
	inline const Color32_t& GetRankColor() const { return m_RankColor; }
private:
	std::string m_TierName; // Iron, Gold, Diamond, Ascendant... etc
	std::string m_FullName;
	Color32_t m_RankColor;
	Rank_t m_Rank;
	std::uint16_t m_Division;
};

class IValorantAct;
class IValorantActPerformance;
class IValorantQueuePerformance
{
public:
	virtual ~IValorantQueuePerformance() {}

	virtual ValorantQueueType_t GetQueueType() const = 0;

	// can return nullptr careful.
	virtual const IValorantActPerformance* GetActPerformance(const UUID_t& ActID) const = 0;

	// can return nullptr careful.
	virtual const IValorantActPerformance* GetActPerformance(const std::shared_ptr<const IValorantAct> pAct) const = 0;

	virtual const IValorantActPerformance& GetCurrentActPerformance() const = 0;
	virtual const IValorantActPerformance& GetPeakActPerformance() const = 0;
};

class IValorantAgentSelect;
class IValorantMatch;
class IValorantPlayer
{
public:
	virtual ~IValorantPlayer() { }
	virtual const UUID_t& GetPlayerID() const = 0;
	virtual const RiotID_t& GetRiotID() const = 0;
	virtual std::uint64_t GetAccountLevel() const = 0;

	virtual bool IsLocalPlayer() const = 0;

	// streamer mode / hidden name on valorant
	virtual bool IsIncognito() const = 0;

	// hidden account level
	virtual bool IsHidingAccountLevel() const = 0;

	// hidden ranked badge
	virtual bool IsActBadgeHidden() const = 0;

	// hidden name on Immortal/Radiant leaderboard
	virtual bool IsLeaderboardAnonymized() const = 0;

	// returns nullptr if can't find queuetype
	virtual const IValorantQueuePerformance& GetQueuePerformance(const ValorantQueueType_t QueueType) const = 0;

	virtual const IValorantActPerformance& GetCurrentCompetitivePerformance() const = 0;

	// returns an act based on the highest rank a win is achieved
	virtual const IValorantActPerformance& GetPeakCompetitivePerformance() const = 0;

	virtual void UpdatePlayerMMR() = 0;
public:
	// only usable if the player is in one of these otherwise 
	// it returns an invalid UUID.  Can be used to tell if a 
	// player is in agent select/game or not.

	// Agent Select / Lobby ID
	virtual UUID_t GetAgentSelectID() const = 0;
	virtual std::shared_ptr<IValorantAgentSelect> GetAgentSelect() const = 0;

	// Current Match ID
	virtual UUID_t GetMatchID() const = 0;
	virtual std::shared_ptr<IValorantMatch> GetMatch() const = 0;
};

class IValorantAgent
{
public:
	virtual ~IValorantAgent() {}
	virtual const std::string& GetName() const = 0;
	virtual const Color32_t& GetColor() const = 0;
};

class IValorantMap
{
public:
	virtual ~IValorantMap() {}
	virtual const std::string& GetName() const = 0;
};

class IValorantMatchPlayer : public virtual IValorantPlayer
{
public:
	// has an agent selected or hovered
	virtual bool HasAgent() const = 0;

	virtual std::shared_ptr<const IValorantAgent> GetAgent() const = 0;

	virtual TeamID_t GetTeam() const = 0;

	virtual Color32_t GetTeamColor() const = 0;
};

class IValorantAgentSelect
{
public:
	virtual ~IValorantAgentSelect() {}
	virtual bool IsValid() const = 0;
	virtual TeamID_t GetTeam() const = 0;
	virtual std::shared_ptr<const IValorantMap> GetMap() const = 0;
	virtual std::vector<const IValorantMatchPlayer*> GetTeammates() const = 0;
};

class IValorantMatch
{
public:
	virtual ~IValorantMatch() {}
	virtual bool IsValid() const = 0;
	virtual std::shared_ptr<const IValorantMap> GetMap() const = 0;
	virtual std::vector<const IValorantMatchPlayer*> GetAttackers() const = 0;
	virtual std::vector<const IValorantMatchPlayer*> GetDefenders() const = 0;
	virtual std::vector<const IValorantMatchPlayer*> GetOtherPlayers() const = 0;
};

class IValorantActPerformance
{
public:
	virtual ~IValorantActPerformance() {}
	virtual std::shared_ptr<const IValorantAct> GetAct() const = 0;
	virtual const ValorantRank_t& GetRank() const = 0;
	virtual bool IsRanked() const = 0;
	virtual bool IsInPlacements() const = 0;
	virtual std::uint64_t GetRankedRating() const = 0;
	virtual std::uint64_t GetWins() const = 0;
	virtual std::uint64_t GetLosses() const = 0;
	virtual std::uint64_t GetNumGames() const = 0;
	virtual float GetWinProbability() const = 0;
	virtual bool HasLeaderboardRank() const = 0;
	virtual std::uint64_t GetLeaderboardRank() const = 0;
	virtual const ValorantRank_t& GetPeakRank() const = 0;
	virtual const std::vector<std::pair<std::uint64_t, ValorantRank_t>>& GetWinsByRank() const = 0;
};

class CValorantAPI;
class IValorantEpisode;
class IValorantAct
{
public:
	virtual ~IValorantAct() {}
	virtual std::uint64_t GetEpisodeNumber() const = 0;
	virtual std::uint64_t GetActNumber() const = 0;
	virtual bool IsActive() const = 0;
	virtual bool IsBeta() const = 0;
	virtual const CTime& GetStartTime() const = 0;
	virtual const CTime& GetEndTime() const = 0;
	virtual const UUID_t& GetUUID() const = 0;
};

class IValorantEpisode
{
public:
	virtual ~IValorantEpisode() {}
	virtual const UUID_t& GetUUID() const = 0;
	virtual bool IsActive() const = 0;
	virtual const CTime& GetStartTime() const = 0;
	virtual const CTime& GetEndTime() const = 0;
};

class IValorantAPI
{
public:
	virtual ~IValorantAPI() { }
	static std::shared_ptr<IValorantAPI> Get();
	virtual std::unique_ptr<IValorantPlayer> GetPlayer(const UUID_t& PlayerID) = 0;
	virtual std::unique_ptr<IValorantPlayer> GetLocalPlayer() = 0;
};

_VALORANT_API_NAMESPACE_END
#endif // RIOTAPI_H