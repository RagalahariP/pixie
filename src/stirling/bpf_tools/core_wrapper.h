#include <bpf/libbpf.h>

#pragma once

namespace px {
namespace stirling {
namespace bpf_tools {

/**
 * Wrapper around CO-RE implementation.
 */
template <typename SkelType>
class COREWrapper {
 public:
  virtual ~COREWrapper() {
   // Cleanup the skel if it's not null
   if (skel) {
      // Replace the following line with the actual cleanup logic
      std::cout << "Cleaning up skel\n";
    }
  }

  COREWrapper() : skel(nullptr) {}
  virtual StatusOr<ebpf::BPF*> BPF() = 0;

  // Open BPF program
  virtual Status OpenCOREBPFProgram()
  {
    // Construct the BPF function name using the prefix
     std::string functionName = getBPFPrefix();
    functionName += "__open";
    skel = functionName+"()";
    if (!skel) {
      std::cout<<"Error\n";
      return 1;
    }
  }

 virtual Close()
 {
   // Closing the program
   std::cout<<"closing";
 }

 private:
    // Skel variable to keep track of the program
    SkelType* skel;
}
