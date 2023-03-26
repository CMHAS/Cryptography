#pragma once
#include <array>
#include <string>
#include <ostream>
#include <vector>
#include <iomanip>

namespace HashLib
{
	class Sha256
	{
	public:
		Sha256() = delete;
		Sha256(const std::string&);
		void CalcHashArray(const std::string& message);
		std::array<unsigned, 8> GetHashArray() const;

		Sha256& operator=(Sha256&) = delete;
		friend std::ostream& operator<<(std::ostream& os, const Sha256& sha);

	private:
		std::array<unsigned, 8> m_h;
		std::array<unsigned, 64> m_w;
		std::vector<unsigned char> m_m;
		void MessagePadding();
		void CompressionFunction();
		void CompressionFunctionMainLoop();
		unsigned RightRotate(const unsigned, const unsigned) const;
		unsigned RightShift(const unsigned, const unsigned) const;
	};

	inline std::ostream& operator<<(std::ostream& os, const Sha256& sha)
	{
		for (const unsigned& h : sha.GetHashArray()) {
			os << std::hex << std::setw(8) << std::setfill('0') << h;
		}
		return os;
	}
}