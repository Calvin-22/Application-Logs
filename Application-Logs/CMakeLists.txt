# CMakeList.txt : projet CMake pour Application-Logs, incluez la source et définissez
# la logique spécifique au projet ici.
#

# Ajoutez une source à l'exécutable de ce projet.
add_executable (Application-Logs "Application-Logs.cpp" "Application-Logs.h")

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET Application-Logs PROPERTY CXX_STANDARD 20)
endif()

# TODO: Ajoutez des tests et installez des cibles si nécessaire.
