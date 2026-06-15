// cppimport
<%
cfg['sources'] = ['extra.cpp']
cfg['include_dirs'] = ['inc']
setup_pybind11(cfg)
%>
#include <pybind11/pybind11.h>
PYBIND11_MODULE(templated, m) {}
