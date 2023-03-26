#include "pch.h"
#include "CppUnitTest.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace HashTest
{
	TEST_CLASS(Hash256Test)
	{
		std::string testStr1 = "123456789_123456789_123456789_123456789_123456789_123456789_123456789_123456789_123456789_123456789_";
	public:
		TEST_METHOD(TestLeadingZero)
		{
			HashLib::Sha256 sha256("   ");
			std::stringstream ss;
			ss << sha256;
			Assert::AreEqual("0aad7da77d2ed59c396c99a74e49f3a4524dcdbcb5163251b1433d640247aeb4", ss.str().c_str());
			ss.seekp(0);
			sha256.CalcHashArray("  ");
			ss << sha256;
			Assert::AreEqual("6c179f21e6f62b629055d8ab40f454ed02e48b68563913473b857d3638e23b28", ss.str().c_str());
		}
		
		TEST_METHOD(StringLength4)
		{
			HashLib::Sha256 sha256("My test");
			std::stringstream ss;
			ss << sha256;
			Assert::AreEqual("a280a9e487a6cc0e8733b70ca173eb11bc3f2e24441a197bc5795c0d73024ae8", ss.str().c_str());
		}

		TEST_METHOD(StringLength100)
		{			
			Assert::AreEqual(100ull, testStr1.size());
			HashLib::Sha256 sha256(testStr1);
			std::stringstream ss;
			ss << sha256;
			Assert::AreEqual("a81fdc751d487fe0e1f707a112807f2637d7485b82659446b38a24a4979fbfb3", ss.str().c_str());
		}

		TEST_METHOD(StringLength1000)
		{
			for (size_t i = 0; i < 9; ++i) {
				testStr1.append("123456789_123456789_123456789_123456789_123456789_123456789_123456789_123456789_123456789_123456789_");
			}
			Assert::AreEqual(1000ull, testStr1.size());
			HashLib::Sha256 sha256(testStr1);
			std::stringstream ss;
			ss << sha256;
			Assert::AreEqual("aecc6ee628c51acf14a68b0480c3d21e2419c201dd9d534f9342f55aab2151cf", ss.str().c_str());
		}

	};
}
