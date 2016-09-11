using System;
using System.Security.Cryptography;
using System.Text;

namespace S22.Scrypt {
	/// <summary>
	/// Implements the password-based key derivation function scrypt.
	/// </summary>
	public class Rfc7914DerivedBytes : DeriveBytes {
		byte[] salt;
		int blockSize;
		int cost;
		int parallelization;

		/// <summary>
		/// Gets or sets the key salt value for the operation.
		/// </summary>
		/// <exception cref="ArgumentNullException">
		/// The property is being set and the new salt value is null.
		/// </exception>
		/// <remarks>
		/// Salt, a random set of bytes, is used to make unauthorized decrypting of a message more
		/// difficult. A dictionary attack is an attack in which the attacker attempts to decrypt
		/// an encrypted message by comparing the encrypted value with previously computed
		/// encrypted values for the most likely keys. This attack is made much more difficult by
		/// the introduction of salt, or random bytes, at the end of the password before the key
		/// derivation.
		/// </remarks>
		public byte[] Salt {
			get {
				return salt;
			}
			set {
				if (value == null)
					throw new ArgumentNullException("The Salt property cannot be null.");
				salt = (byte[])value.Clone();
			}
		}

		/// <summary>
		/// Gets or sets the block size parameter for the operation.
		/// </summary>
		/// <remarks>
		/// At the current time (August 2016), a block size of 8 appears to yield good results.
		/// </remarks>
		/// <exception cref="ArgumentException">
		/// The property is being set and the new value is less than or equal to 0.
		/// </exception>
		public int BlockSize {
			get {
				return blockSize;
			}
			set {
				if (value < 1)
					throw new ArgumentException($"Invalid value {value} for BlockSize.");
				blockSize = value;
			}
		}

		/// <summary>
		/// Gets or sets the CPU/Memory cost parameter for the operation.
		/// </summary>
		/// <remarks>
		/// The CPU/Memory cost parameter must be larger than 1, a power of 2, and less than
		/// 2^(128 * <see cref="BlockSize"/> / 8).
		/// </remarks>
		/// <exception cref="ArgumentException">
		/// The property is being set and the new value is less than or equal to 1, or the new
		/// value is not a power of 2.
		/// </exception>
		public int Cost {
			get {
				return cost;
			}
			set {
				if((value < 2) || ((value & (value - 1)) != 0))
					throw new ArgumentException($"Invalid value {value} for Cost.");
				cost = value;
			}
		}

		/// <summary>
		/// Gets or sets the Parallelization parameter for the operation.
		/// </summary>
		/// <remarks>
		/// The parallelization parameter is a positive integer less than or equal to
		/// ((2^32-1) * 32) / (128 * <see cref="BlockSize"/>).
		/// </remarks>
		/// <exception cref="ArgumentException">
		/// The property is being set and the new value is negative.
		/// </exception>
		public int Parallelization {
			get {
				return parallelization;
			}
			set {
				if (value < 0)
					throw new ArgumentException($"Invalid value {value} for Parallelization.");
				parallelization = value;
			}
		}

		/// <summary>
		/// Initializes a new instance of the Rfc7914DerivedBytes class using a password, a salt,
		/// and optionally a block size and values for the parallelization and cost
		/// parameters of the scrypt function.
		/// </summary>
		/// <param name="password">
		/// The password used to derive the key.
		/// </param>
		/// <param name="salt">
		/// The key salt used to derive the key.
		/// </param>
		/// <param name="blockSize">
		/// The block size for the operation.
		/// </param>
		/// <param name="parallelization">
		/// The parallelization parameter for the operation.
		/// </param>
		/// <param name="cost">
		/// The CPU/Memory cost parameter for the operation.
		/// </param>
		/// <exception cref="ArgumentNullException">
		/// The <paramref name="password"/> parameter or the <paramref name="salt"/> parameter is
		/// null.
		/// </exception>
		/// <exception cref="ArgumentException">
		/// The <paramref name="blockSize"/> parameter is less than one, or the
		/// <paramref name="parallelization"/> is less than one, or the <paramref name="cost"/>
		/// parameter is less than two or not a power of two.
		/// </exception>
		public Rfc7914DerivedBytes(byte[] password, byte[] salt, int blockSize = 8,
			int parallelization = 1, int cost = 16384) {
			if (password == null)
				throw new ArgumentNullException(nameof(password));
			Salt = salt;
			BlockSize = blockSize;
			Parallelization = parallelization;
			Cost = cost;
		}

		/// <summary>
		/// Initializes a new instance of the Rfc7914DerivedBytes class using a password, a salt
		/// size, and optionally a block size and values for the parallelization and cost
		/// parameters of the scrypt function.
		/// </summary>
		/// <param name="password">
		/// The password used to derive the key.
		/// </param>
		/// <param name="saltSize">
		/// The size of the random salt that you want the class to generate.
		/// </param>
		/// <param name="blockSize">
		/// The block size for the operation.
		/// </param>
		/// <param name="parallelization">
		/// The parallelization parameter for the operation.
		/// </param>
		/// <param name="cost">
		/// The CPU/Memory cost parameter for the operation.
		/// </param>
		/// <exception cref="ArgumentNullException">
		/// The <paramref name="password"/> parameter is null.
		/// </exception>
		/// <exception cref="ArgumentException">
		/// The <paramref name="saltSize"/> parameter is less than 1, or the <paramref name="blockSize"/>
		/// parameter is less than one, or the <paramref name="parallelization"/> is less than
		/// one, or the <paramref name="cost"/> parameter is less than two or not a power of two.
		/// </exception>
		public Rfc7914DerivedBytes(byte[] password, int saltSize, int blockSize = 8,
			int parallelization = 1, int cost = 16384)
			: this(password, GetRandomBytes(saltSize), blockSize, parallelization, cost) {
		}

		/// <summary>
		/// Initializes a new instance of the Rfc7914DerivedBytes class using a password, a salt
		/// size, and optionally a block size and values for the parallelization and cost
		/// parameters of the scrypt function.
		/// </summary>
		/// <param name="password">
		/// The password used to derive the key.
		/// </param>
		/// <param name="saltSize">
		/// The size of the random salt that you want the class to generate.
		/// </param>
		/// <param name="blockSize">
		/// The block size for the operation.
		/// </param>
		/// <param name="parallelization">
		/// The parallelization parameter for the operation.
		/// </param>
		/// <param name="cost">
		/// The CPU/Memory cost parameter for the operation.
		/// </param>
		/// <exception cref="ArgumentNullException">
		/// The <paramref name="password"/> parameter is null.
		/// </exception>
		/// <exception cref="ArgumentException">
		/// The <paramref name="saltSize"/> parameter is less than 1, or the <paramref name="blockSize"/>
		/// parameter is less than one, or the <paramref name="parallelization"/> is less than
		/// one, or the <paramref name="cost"/> parameter is less than two or not a power of two.
		/// </exception>
		public Rfc7914DerivedBytes(string password, int saltSize, int blockSize = 8,
			int parallelization = 1, int cost = 16384)
			: this(Encoding.UTF8.GetBytes(password), saltSize, blockSize, parallelization, cost) {
		}

		/// <summary>
		/// Initializes a new instance of the Rfc7914DerivedBytes class using a password, a salt,
		/// and optionally a block size and values for the parallelization and cost
		/// parameters of the scrypt function.
		/// </summary>
		/// <param name="password">
		/// The password used to derive the key.
		/// </param>
		/// <param name="salt">
		/// The key salt used to derive the key.
		/// </param>
		/// <param name="blockSize">
		/// The block size for the operation.
		/// </param>
		/// <param name="parallelization">
		/// The parallelization parameter for the operation.
		/// </param>
		/// <param name="cost">
		/// The CPU/Memory cost parameter for the operation.
		/// </param>
		/// <exception cref="ArgumentNullException">
		/// The <paramref name="password"/> parameter or the <paramref name="salt"/> parameter is
		/// null.
		/// </exception>
		/// <exception cref="ArgumentException">
		/// The <paramref name="blockSize"/> parameter is less than one, or the
		/// <paramref name="parallelization"/> is less than one, or the <paramref name="cost"/>
		/// parameter is less than two or not a power of two.
		/// </exception>
		public Rfc7914DerivedBytes(string password, byte[] salt, int blockSize = 8,
			int parallelization = 1, int cost = 16384)
			: this(Encoding.UTF8.GetBytes(password), salt, blockSize, parallelization, cost) {
		}

		/// <summary>
		/// Returns the pseudo-random key for this object.
		/// </summary>
		/// <param name="cb">
		/// The number of pseudo-random key bytes to generate.
		/// </param>
		/// <returns>
		/// A byte array filled with pseudo-random key bytes.
		/// </returns>
		/// <exception cref="ArgumentOutOfRangeException">
		/// The cb parameter is out of range. This parameter requires a non-negative number.
		/// </exception>
		/// <remarks>
		/// 
		/// </remarks>
		public override byte[] GetBytes(int cb) {
			throw new NotImplementedException();
		}

		/// <summary>
		/// Resets the state of the operation.
		/// </summary>
		/// <remarks>
		/// This method is automatically called if the <see cref="Salt"/>, <see cref="BlockSize"/>,
		/// <see cref="Cost"/> or <see cref="Parallelization"/> parameter is modified.
		/// </remarks>
		public override void Reset() {
			throw new NotImplementedException();
		}

		byte[] Salsa(byte[] input) {
			throw new NotImplementedException();
		}

		byte[] ScryptBlockMix(byte[] input) {
			throw new NotImplementedException();
		}

		byte[] ScryptROMix(byte[] input) {
			throw new NotImplementedException();
		}

		/// <summary>
		/// Gets an array of bytes with a cryptographically strong sequence of random values of
		/// the specified size.
		/// </summary>
		/// <param name="size">
		/// The size of the array, in bytes.
		/// </param>
		/// <returns>
		/// An array of bytes with a cryptographically strong sequence of random values of the
		/// specified size.
		/// </returns>
		/// <exception cref="ArgumentException">
		/// The size parameter is less than or equal to 0.
		/// </exception>
		static byte[] GetRandomBytes(int size) {
			if (size <= 0)
				throw new ArgumentException(nameof(size));
			var bytes = new byte[size];
			using (var csp = new RNGCryptoServiceProvider())
				csp.GetBytes(bytes);
			return bytes;
		}
	}
}
