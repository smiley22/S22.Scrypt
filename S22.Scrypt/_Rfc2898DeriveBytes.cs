// ==++== 
//
//   Copyright (c) Microsoft Corporation.  All rights reserved.
//
// ==--== 

// 
// Rfc2898DeriveBytes.cs 
//

// This implementation follows RFC 2898 recommendations. See http://www.ietf.org/rfc/Rfc2898.txt
// It uses HMACSHA1 as the underlying pseudorandom function.

// Smiley22:
//  Adapted to allow for specifying the pseudo-random generator function to use with PBKDF2
//  (.NET's implementation in System.Security.Cryptography is hard-wired to HMACSHA1).

using System;
using System.Security.Cryptography;
using System.Text;

namespace S22.Scrypt {
	internal class _Rfc2898DeriveBytes : DeriveBytes {
		private byte[] m_buffer;
		private byte[] m_salt;
		// S22: Adapted to allow for configuring the pseudo-random generator function to use.
		private readonly HMAC m_hmac;

		private uint m_iterations;
		private uint m_block;
		private int m_startIndex;
		private int m_endIndex;

		private readonly int m_blockSize;

		static string GetResourceString(string s) {
			return s;
		}

		static byte[] Int(uint i) {
			byte[] b = BitConverter.GetBytes(i);
			byte[] littleEndianBytes = { b[3], b[2], b[1], b[0] };
			return BitConverter.IsLittleEndian ? littleEndianBytes : b;
		}

		//
		// public constructors 
		// 

		public _Rfc2898DeriveBytes(string password, int saltSize) : this(password, saltSize, 1000, null) { }

		public _Rfc2898DeriveBytes(string password, int saltSize, int iterations, HMAC hmac) {
			if (saltSize < 0)
				throw new ArgumentOutOfRangeException("saltSize", GetResourceString("ArgumentOutOfRange_NeedNonNegNum"));

			byte[] salt = new byte[saltSize];
			var csp = new RNGCryptoServiceProvider();
			csp.GetBytes(salt);

			Salt = salt;
			IterationCount = iterations;
			if (hmac == null)
				m_hmac = new HMACSHA1(new UTF8Encoding(false).GetBytes(password));
			else
				m_hmac = hmac;
			m_blockSize = m_hmac.HashSize / 8;
			Initialize();
		}

		public _Rfc2898DeriveBytes(string password, byte[] salt) : this(password, salt, 1000, null) { }

		public _Rfc2898DeriveBytes(string password, byte[] salt, int iterations, HMAC hmac) : this(new UTF8Encoding(false).GetBytes(password), salt, iterations, hmac) { }

		public _Rfc2898DeriveBytes(byte[] password, byte[] salt, int iterations, HMAC hmac) {
			Salt = salt;
			IterationCount = iterations;
			if (hmac == null)
				m_hmac = new HMACSHA1(password);
			else
				m_hmac = hmac;
			m_blockSize = m_hmac.HashSize / 8;
			Initialize();
		}

		//
		// public properties 
		//

		public int IterationCount {
			get { return (int)m_iterations; }
			set {
				if (value <= 0)
					throw new ArgumentOutOfRangeException("value", GetResourceString("ArgumentOutOfRange_NeedNonNegNum"));
				m_iterations = (uint)value;
				Initialize();
			}
		}

		public byte[] Salt {
			get { return (byte[])m_salt.Clone(); }
			set {
				if (value == null)
					throw new ArgumentNullException("value");
				//if (value.Length < 8)
				//	throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, GetResourceString("Cryptography_PasswordDerivedBytes_FewBytesSalt")));
				m_salt = (byte[])value.Clone();
				Initialize();
			}
		}

		// 
		// public methods
		// 

		public override byte[] GetBytes(int cb) {
			if (cb <= 0)
				throw new ArgumentOutOfRangeException("cb", GetResourceString("ArgumentOutOfRange_NeedNonNegNum"));
			byte[] password = new byte[cb];

			int offset = 0;
			int size = m_endIndex - m_startIndex;
			if (size > 0) {
				if (cb >= size) {
					Buffer.BlockCopy(m_buffer, m_startIndex, password, 0, size);
					m_startIndex = m_endIndex = 0;
					offset += size;
				} else {
					Buffer.BlockCopy(m_buffer, m_startIndex, password, 0, cb);
					m_startIndex += cb;
					return password;
				}
			}

			while (offset < cb) {
				byte[] T_block = Func();
				int remainder = cb - offset;
				if (remainder > m_blockSize) {
					Buffer.BlockCopy(T_block, 0, password, offset, m_blockSize);
					offset += m_blockSize;
				} else {
					Buffer.BlockCopy(T_block, 0, password, offset, remainder);
					offset += remainder;
					Buffer.BlockCopy(T_block, remainder, m_buffer, m_startIndex, m_blockSize - remainder);
					m_endIndex += (m_blockSize - remainder);
					return password;
				}
			}
			return password;
		}

		public override void Reset() {
			Initialize();
		}

		private void Initialize() {
			if (m_buffer != null)
				Array.Clear(m_buffer, 0, m_buffer.Length);
			m_buffer = new byte[m_blockSize];
			m_block = 1;
			m_startIndex = m_endIndex = 0;
		}

		// This function is defined as follow : 
		// Func (S, i) = HMAC(S || i) | HMAC2(S || i) | ... | HMAC(iterations) (S || i)
		// where i is the block number. 
		private byte[] Func() {
			byte[] INT_block = Int(m_block);

			m_hmac.TransformBlock(m_salt, 0, m_salt.Length, m_salt, 0);
			m_hmac.TransformFinalBlock(INT_block, 0, INT_block.Length);
			byte[] temp = m_hmac.Hash;
			m_hmac.Initialize();

			byte[] ret = temp;
			for (int i = 2; i <= m_iterations; i++) {
				temp = m_hmac.ComputeHash(temp);
				for (int j = 0; j < m_blockSize; j++) {
					ret[j] ^= temp[j];
				}
			}

			// increment the block count.
			m_block++;
			return ret;
		}
	}
}

// File provided for Reference Use Only by Microsoft Corporation (c) 2007.
