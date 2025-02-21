#ifndef KEYGEN_H
#define KEYGEN_H

#include <vector>
#include "setup.h"

// Wrapper class for element_t to manage PBC elements in STL containers
class ElementWrapper {
public:
    element_t elem;

    // Default constructor
    ElementWrapper() : elem(nullptr) {}

    // Constructor with group initialization
    ElementWrapper(pairing_t& pairing, int groupType) {
        elem = new element_s;
        switch (groupType) {
            case 0: element_init_Zr(elem, pairing); break;  // Zr
            case 1: element_init_G1(elem, pairing); break;  // G1
            case 2: element_init_G2(elem, pairing); break;  // G2
            default: throw std::runtime_error("Invalid group type");
        }
    }

    // Copy constructor
    ElementWrapper(const ElementWrapper& other) : elem(nullptr) {
        if (other.elem) {
            elem = new element_s;
            element_init_same_as(elem, other.elem);
            element_set(elem, other.elem);
        }
    }

    // Move constructor
    ElementWrapper(ElementWrapper&& other) noexcept : elem(other.elem) {
        other.elem = nullptr;
    }

    // Destructor
    ~ElementWrapper() {
        if (elem) {
            element_clear(elem);
            delete elem;
        }
    }

    // Assignment operator (copy)
    ElementWrapper& operator=(const ElementWrapper& other) {
        if (this != &other) {
            if (elem) {
                element_clear(elem);
                delete elem;
            }
            elem = nullptr;
            if (other.elem) {
                elem = new element_s;
                element_init_same_as(elem, other.elem);
                element_set(elem, other.elem);
            }
        }
        return *this;
    }

    // Move assignment
    ElementWrapper& operator=(ElementWrapper&& other) noexcept {
        if (this != &other) {
            if (elem) {
                element_clear(elem);
                delete elem;
            }
            elem = other.elem;
            other.elem = nullptr;
        }
        return *this;
    }
};

// Structure for each Election Authority's (EA) key pair
struct EAKey {
    ElementWrapper sgk1; // Signing key share 1: ∑_{l∈Q} Fl(i) in Zr
    ElementWrapper sgk2; // Signing key share 2: ∑_{l∈Q} Gl(i) in Zr
    ElementWrapper vkm1; // Verification key component 1: g2^sgk1 in G2
    ElementWrapper vkm2; // Verification key component 2: g2^sgk2 in G2
    ElementWrapper vkm3; // Verification key component 3: g1^sgk2 in G1

    EAKey(pairing_t& pairing) 
        : sgk1(pairing, 0), sgk2(pairing, 0), 
          vkm1(pairing, 2), vkm2(pairing, 2), vkm3(pairing, 1) {}
};

// Structure for the master verification key (mvk)
struct MasterVK {
    ElementWrapper alpha2; // g2^(∑ xi0) in G2
    ElementWrapper beta2;  // g2^(∑ yi0) in G2
    ElementWrapper beta1;  // g1^(∑ yi0) in G1

    MasterVK(pairing_t& pairing) 
        : alpha2(pairing, 2), beta2(pairing, 2), beta1(pairing, 1) {}
};

// Output structure for key generation
struct KeyGenOutput {
    MasterVK mvk;
    std::vector<EAKey> eaKeys;

    KeyGenOutput(pairing_t& pairing) : mvk(pairing) {}
};

// Function to perform Coconut TTP-less key generation
KeyGenOutput keygen(TIACParams params, int t, int ne);

#endif