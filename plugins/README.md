# marauder

### INTRODUCTION ###
Introduction
This is a design document which outlines the approach to enable multifactor authentication in keycloak for NG vuSmartMaps.

### REQUIREMENT ###
#### JDK: 21.0 ####
#### Maven: 3.5+ ####
#### Keycloak version: 22.0.0 ####

### Prerequsite ###
#### Keycloak Repository must be build first ###
``` git clone https://github.com/vunetsystems/washington.git ```

#### Build Keycloak ####
``` mvn clean install -DskipTests=true -DskipTestsuite ```

### Build Marauder ###
#### Use the same version of keycloak build in above step #### 
```mvn clean install```

### Document Link ###
#### Authenticator: ####
https://docs.google.com/document/d/1ZgmIBRCooFzkABXbI-xrOlOl9cHXY1K6nKNS4QLygZ4/edit?usp=sharing
#### SMS ####
https://docs.google.com/document/d/1AESK96KtTuRIiWTG9M9uModZHvg4Sp4lWNXP8OiTTjM/edit?usp=sharing

#### Maven Dependency Tree ####
https://drive.google.com/file/d/1f3QADIiW4pXS-6sI-S2MzTmGBGbekqb4/view?usp=sharing