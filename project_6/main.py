import random
from tinyec import registry
import hashlib
from phe import paillier

class Party1:
    """
    Implements the role of Party 1 in the DDH-based Private Intersection-Sum protocol.
    """
    def __init__(self, V_set):
        """
        Initializes Party 1 with its set of identifiers.

        Args:
            V_set (list): A list of identifiers for Party 1.
        """
        self.V_set = V_set
        self.curve = registry.get_curve('secp256r1')
        self.k1 = random.randint(1, self.curve.field.n - 1)
        self.pk = None
        self.shuffled_j_to_r_map = {}

    def _hash_to_curve(self, identifier):
        """
        Hashes an identifier to a point on the elliptic curve.

        Args:
            identifier (str): The identifier to hash.

        Returns:
            Point: A point on the elliptic curve corresponding to the identifier.
        """
        # A simple way to hash to the curve for demonstration purposes.
        # This is not a secure way to do it in a real-world application.
        # See the paper for more on secure hashing to a curve.
        x_val = int(hashlib.sha256(identifier.encode()).hexdigest(), 16) % self.curve.field.n
        while True:
            try:
                # We will try to find a valid y for the given x
                # This is not always possible and a more robust method is needed in practice.
                y_sq = (x_val**3 + self.curve.a * x_val + self.curve.b) % self.curve.field.p
                y_val = pow(y_sq, (self.curve.field.p + 1) // 4, self.curve.field.p)
                if pow(y_val, 2, self.curve.field.p) == y_sq:
                    return self.curve.g * x_val # Simplified for demonstration
            except Exception:
                x_val = (x_val + 1) % self.curve.field.n


    def round_1(self):
        """
        Executes Round 1 of the protocol for Party 1.
        Hashes and exponentiates its identifiers.

        Returns:
            list: A shuffled list of exponentiated identifiers.
        """
        hashed_and_exponentiated_V = [self._hash_to_curve(v) * self.k1 for v in self.V_set]
        random.shuffle(hashed_and_exponentiated_V)
        return hashed_and_exponentiated_V

    def round_3(self, Z_set, w_hashed_and_encrypted_set):
        """
        Executes Round 3 of the protocol for Party 1.
        Computes the intersection and the homomorphic sum.

        Args:
            Z_set (list): The set Z received from Party 2 in Round 2.
            w_hashed_and_encrypted_set (list): The set of hashed and encrypted pairs from P2.

        Returns:
            tuple: A tuple containing the encrypted intersection sum and the intersection set.
        """
        # P1 exponentiates the first member of the pair from P2
        H_w_k2_k1_set = [(item[0] * self.k1, item[1]) for item in w_hashed_and_encrypted_set]

        # Compute the intersection set J
        Z_set_coords = [(p.x, p.y) for p in Z_set]
        J_set = []
        intersection_ciphertexts = []

        for w_exp, encrypted_t in H_w_k2_k1_set:
            if (w_exp.x, w_exp.y) in Z_set_coords:
                J_set.append(w_exp)
                intersection_ciphertexts.append(encrypted_t)

        # Homomorphically add the associated ciphertexts
        if intersection_ciphertexts:
            encrypted_intersection_sum = intersection_ciphertexts[0]
            for i in range(1, len(intersection_ciphertexts)):
                encrypted_intersection_sum += intersection_ciphertexts[i]

            # Randomize the ciphertext using ARefresh (achieved by adding an encryption of 0)
            encrypted_intersection_sum = encrypted_intersection_sum + self.pk.encrypt(0)

            return encrypted_intersection_sum, J_set
        else:
            return self.pk.encrypt(0), []


class Party2:
    """
    Implements the role of Party 2 in the DDH-based Private Intersection-Sum protocol.
    """
    def __init__(self, W_set_of_pairs):
        """
        Initializes Party 2 with its set of identifier-value pairs.

        Args:
            W_set_of_pairs (dict): A dictionary of identifier-value pairs.
        """
        self.W_set_of_pairs = W_set_of_pairs
        self.curve = registry.get_curve('secp256r1')
        self.k2 = random.randint(1, self.curve.field.n - 1)
        self.pk, self.sk = paillier.generate_paillier_keypair()

    def _hash_to_curve(self, identifier):
        """
        Hashes an identifier to a point on the elliptic curve.
        """
        x_val = int(hashlib.sha256(identifier.encode()).hexdigest(), 16) % self.curve.field.n
        while True:
            try:
                y_sq = (x_val**3 + self.curve.a * x_val + self.curve.b) % self.curve.field.p
                y_val = pow(y_sq, (self.curve.field.p + 1) // 4, self.curve.field.p)
                if pow(y_val, 2, self.curve.field.p) == y_sq:
                    return self.curve.g * x_val
            except Exception:
                x_val = (x_val + 1) % self.curve.field.n

    def round_2(self, H_v_k1_set):
        """
        Executes Round 2 of the protocol for Party 2.

        Args:
            H_v_k1_set (list): The shuffled list from Party 1's Round 1.

        Returns:
            tuple: A tuple containing set Z and the set of hashed and encrypted pairs.
        """
        # Step 1 & 2: P2 exponentiates received elements and shuffles
        Z = [h_v_k1 * self.k2 for h_v_k1 in H_v_k1_set]
        random.shuffle(Z)

        # Step 3 & 4: P2 processes its own set
        w_hashed_and_encrypted = []
        for w, t in self.W_set_of_pairs.items():
            h_w = self._hash_to_curve(w)
            h_w_k2 = h_w * self.k2
            encrypted_t = self.pk.encrypt(t)
            w_hashed_and_encrypted.append((h_w_k2, encrypted_t))

        random.shuffle(w_hashed_and_encrypted)
        return Z, w_hashed_and_encrypted

    def get_intersection_sum(self, encrypted_sum):
        """
        Decrypts the final encrypted sum to get the result.

        Args:
            encrypted_sum (Paillier.EncryptedNumber): The encrypted intersection sum from P1.

        Returns:
            int: The decrypted intersection sum.
        """
        return self.sk.decrypt(encrypted_sum)

# --- Main Execution ---
if __name__ == "__main__":
    # 1. Setup
    # P1's set of identifiers
    V = ['user1', 'user2', 'user3', 'user4', 'user5', 'user9']
    # P2's set of identifiers and associated values
    W = {'user3': 100, 'user5': 250, 'user6': 50, 'user7': 80, 'user9': 120}

    party1 = Party1(V)
    party2 = Party2(W)

    print("--- Protocol Execution ---")

    # Both parties agree on the public key for homomorphic encryption
    party1.pk = party2.pk

    # 2. Round 1 (P1)
    print("\nExecuting Round 1 (P1)...")
    p1_round1_output = party1.round_1()
    print("P1 sends a shuffled set of its exponentiated identifiers to P2.")

    # 3. Round 2 (P2)
    print("\nExecuting Round 2 (P2)...")
    Z_set, w_hashed_and_encrypted_set = party2.round_2(p1_round1_output)
    print("P2 processes P1's data and its own, then sends two shuffled sets back to P1.")

    # 4. Round 3 (P1)
    print("\nExecuting Round 3 (P1)...")
    encrypted_intersection_sum, J = party1.round_3(Z_set, w_hashed_and_encrypted_set)
    print("P1 computes the intersection and the encrypted sum, then sends the encrypted sum to P2.")
    print(f"Intersection Cardinality (size of J): {len(J)}")

    # 5. Output (P2)
    print("\nFinal Output (P2)...")
    intersection_sum = party2.get_intersection_sum(encrypted_intersection_sum)
    print(f"The private intersection-sum is: {intersection_sum}")

    # --- Verification ---
    print("\n--- Verification ---")
    intersection_ids = set(V).intersection(set(W.keys()))
    expected_sum = sum(W[id] for id in intersection_ids)
    print(f"Expected intersection identifiers: {intersection_ids}")
    print(f"Expected intersection sum: {expected_sum}")

    assert intersection_sum == expected_sum
    print("\nProtocol executed successfully and the result is correct!")