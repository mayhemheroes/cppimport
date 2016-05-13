# Import C++ files directly from Python!

**The technical description:** cppimport is a small import hook that determines whether there is a C++ source file that matches the requested module. If there is, the file is compiled as a Python extension using [https://github.com/pybind/pybind11](pybind11) and placed in the same folder as the C++ source file. Python is then able to find the module and load it. 

**Simpler language please:** Sometimes Python just isn't fast enough. Or you have existing code in a C++ library. So, you write a Python *extension module*, a library of compiled code. I recommend [https://github.com/pybind/pybind11](pybind11) for the C++ <--> Python bindings. I've done this a lot over the years. But, I discovered that my productivity goes through the floor when my development process goes from *Edit -> Test* in just Python to *Edit -> Compile -> Test* in Python plus C++. So, `cppimport` modifies the import process in Python so that you can type `import cppmodulename`, to import compile and import a C++ extension. Internally, when no matching Python module is found, `cppimport` looks for a file `cppmodulename.cpp`. If one is found, it is compiled and loaded as an extension module.

I'm a big fan of the workflow that this enables, where you can edit both C++ files and Python and recompilation happens transparently.

# Installation
You probably just need to run `pip install cppimport`. 
Two caveats:
* If you a super old compiler that doesn't support c++11, then it won't work. 
* cppimport has only been tested on Unix, so if you'd like to use it on Windows, I'd love to see a pull request with the necessary fixes!

# Let's try it
Here's a simple C++ extension using [https://github.com/pybind/pybind11](pybind11):
```c++
#include <pybind11/pybind11.h>

namespace py = pybind11;

int square(int x) {
    return x * x;
}

void pyexport(py::module& m) {
    m.def("square", &square);
}
```
The `pyexport` function specifies which functions (or classes) are available from python [1].

Save this code as `somecode.cpp`.

Open a python interpreter and run these lines:
```
>>> import cppimport
>>> import somecode #This will pause for a moment to compile the module [2]
>>> somecode.square(9)
81
```

Voila! 

Now, go look at the [https://github.com/pybind/pybind11](pybind11) documentation for all the cool stuff you can do!

#### Notes
[1]: the pyexport function is called by an auto-generated PYBIND11_PLUGIN call, so that the module name can be substituted in by cppimport

[2]: The compilation should only happen the first time the module is imported. The C++ source is compared with a checksum on each import to determine if the file has changed.

[3]: Calling `cppimport.set_quiet(False)` will result in output that will be helpful in debugging compile errors. The default is to make the import process completely silent.

[4]: If you have a more complex extension that requires adding include directories, multiple source files, or libraries, this project isn't currently useful for you. Let me know if you have suggestions on how to include these features smoothly.

# cppimport uses the MIT License
