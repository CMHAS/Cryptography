#include "Sha256.h"

using namespace HashLib;

constexpr	int batchLength = 64; // 64 = 512 / 8
constexpr	std::array<unsigned, 64> k{ 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
										0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
										0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
										0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
										0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
										0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
										0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
										0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

constexpr	std::array<unsigned, 8> init{ 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

Sha256::Sha256(const std::string& message)
{
	this->CalcHashArray(message);
}

void Sha256::CalcHashArray(const std::string& message)
{
	m_h = init;
	m_m.resize(message.size());
	for (size_t i = 0; i < message.size(); ++i) {
		m_m.at(i) = static_cast<unsigned char>(message.at(i));
	}
	this->MessagePadding();
	this->CompressionFunction();
}

std::array<unsigned, 8> Sha256::GetHashArray() const
{
	return m_h;
}

void Sha256::MessagePadding()
{
	const size_t K = m_m.size() * 8;
	m_m.push_back(0x80);
	const size_t padCnt = batchLength - (m_m.size() % batchLength);
	const size_t newSize = (m_m.size() + padCnt) + (padCnt >= 8 ? 0 : 64);
	m_m.resize(newSize);

	for (size_t i = 8; i > 0; --i) {
		const size_t iMul = i * 8;
		m_m.at(m_m.size() - i) = static_cast<unsigned char>((K & (0xff00000000000000 >> (64 - iMul))) >> (iMul - 8));
	}
}

void Sha256::CompressionFunction()
{
	for (size_t i = 0; i < m_m.size(); i += batchLength) {
		for (size_t j = i; j < (batchLength + i); j += 4) {
			m_w.at((j - i) / 4) = (m_m.at(j) << 24) | (m_m.at(j + 1) << 16) | (m_m.at(j + 2) << 8) | m_m.at(j + 3);
		}
		for (size_t j = 16; j < batchLength; ++j) {
			const unsigned s0 = RightRotate(m_w.at(j - 15), 7) ^ RightRotate(m_w.at(j - 15), 18) ^ RightShift(m_w.at(j - 15), 3);
			const unsigned s1 = RightRotate(m_w.at(j - 2), 17) ^ RightRotate(m_w.at(j - 2), 19) ^ RightShift(m_w.at(j - 2), 10);
			m_w.at(j) = m_w.at(j - 16) + s0 + m_w.at(j - 7) + s1;
		}
		CompressionFunctionMainLoop();
	}
}

void Sha256::CompressionFunctionMainLoop()
{
	std::array<unsigned, 8> aToh = m_h; // Initialize working variables, a, b, c, d, e, f, g, h
	for (size_t i = 0; i < 64; ++i) {
		const unsigned ch = (aToh.at(4) & aToh.at(5)) ^ ((~aToh.at(4)) & aToh.at(6));
		const unsigned ma = (aToh.at(0) & aToh.at(1)) ^ (aToh.at(0) & aToh.at(2)) ^ (aToh.at(1) & aToh.at(2));
		const unsigned s0 = RightRotate(aToh.at(0), 2) ^ RightRotate(aToh.at(0), 13) ^ RightRotate(aToh.at(0), 22);
		const unsigned s1 = RightRotate(aToh.at(4), 6) ^ RightRotate(aToh.at(4), 11) ^ RightRotate(aToh.at(4), 25);
		const unsigned t1 = aToh.at(7) + s1 + ch + k.at(i) + m_w.at(i);
		const unsigned t2 = s0 + ma;

		for (size_t j = 7; j > 0; --j) {
			aToh.at(j) = aToh.at(j - 1);
		}
		aToh.at(4) += t1;
		aToh.at(0) = t1 + t2;
	}

	/*  Add the compressed chunk to the current hash value */
	for (auto& h : m_h) {
		h += aToh.at(&h - &m_h[0]);
	}
}

unsigned Sha256::RightRotate(const unsigned n, const unsigned d) const
{
	return (n >> d) | (n << (8 * sizeof(n) - d));
}

unsigned Sha256::RightShift(const unsigned n, const unsigned d) const
{
	return (n >> d);
}
