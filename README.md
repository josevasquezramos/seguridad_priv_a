<p align="center"><a href="https://www.uns.edu.pe" target="_blank"><img src="https://upload.wikimedia.org/wikipedia/commons/1/1a/Universidad_Nacional_del_Santa_Logo.png" width="250" alt="UNS Logo"></a></p>

<p align="center">
  <a href="https://developer.android.com/" target="_blank"><img src="https://img.shields.io/badge/Android-0F9D58?style=for-the-badge&logo=android&logoColor=white" alt="Android"></a>
  <a href="https://kotlinlang.org/" target="_blank"><img src="https://img.shields.io/badge/Kotlin-7F52FF?style=for-the-badge&logo=kotlin&logoColor=white" alt="Kotlin"></a>
  <a href="https://developer.android.com/topic/security" target="_blank"><img src="https://img.shields.io/badge/Android_Security-737373?style=for-the-badge&logo=android&logoColor=white" alt="Android Security"></a>
  <a href="https://github.com/bumptech/glide" target="_blank"><img src="https://img.shields.io/badge/Glide-737373?style=for-the-badge&logo=github&logoColor=white" alt="Glide"></a>
</p>

<p align="center">
  <a href="https://developer.android.com/training/sign-in/biometric-auth" target="_blank"><img src="https://img.shields.io/badge/Biometric_Authentication-273DAB?style=for-the-badge&logo=google-chrome&logoColor=white" alt="Biometric Auth"></a>
  <a href="https://developer.android.com/training/data-storage/room" target="_blank"><img src="https://img.shields.io/badge/Room_SQLite-1A73E8?style=for-the-badge&logo=sqlite&logoColor=white" alt="Room SQLite"></a>
  <a href="https://www.sqlite.org/" target="_blank"><img src="https://img.shields.io/badge/SQLCipher-1A73E8?style=for-the-badge&logo=sqlite&logoColor=white" alt="SQLCipher"></a>
</p>

# App de Seguridad y Privacidad

Una aplicación Android que demuestra el manejo seguro de permisos y protección de datos personales.

## 📁 Recursos

### 🔗 Documentos importantes

- [**Resolución de la consigna**](https://github.com/josevasquezramos/seguridad_priv_a/blob/master/RESOLUCION.md)

### 📚 Entregables

1. [**Código fuente**](https://github.com/josevasquezramos/seguridad_priv_a/) de todas las implementaciones solicitadas
2. [**Informe técnico**](https://github.com/josevasquezramos/seguridad_priv_a/blob/master/informe_tecnico.pdf) detallando vulnerabilidades encontradas y soluciones aplicadas
3. [**Diagramas de arquitectura**](https://github.com/josevasquezramos/seguridad_priv_a/blob/master/ARQUITECTURA.md) para componentes de seguridad nuevos
4. [**Suite de pruebas**](https://github.com/josevasquezramos/seguridad_priv_a/tree/master/app/src/androidTest/java/com/example/seguridad_priv_a) automatizadas para validar medidas de seguridad
5. [**Manual de deployment**](https://github.com/josevasquezramos/seguridad_priv_a/blob/master/manual_deployment.pdf) con consideraciones de seguridad para producción

## 📷 Capturas

<img width="250" alt="image" src="img/1.jpeg" />
<img width="250" alt="image" src="img/2.jpeg" />
<img width="250" alt="image" src="img/3.jpeg" />
<img width="250" alt="image" src="img/4.jpeg" />
<img width="250" alt="image" src="img/5.jpeg" />
<img width="250" alt="image" src="img/6.jpeg" />
<img width="250" alt="image" src="img/7.jpeg" />
<img width="250" alt="image" src="img/8.jpeg" />
<img width="250" alt="image" src="img/9.jpeg" />
<img width="250" alt="image" src="img/10.jpeg" />
<img width="250" alt="image" src="img/11.jpeg" />
<img width="250" alt="image" src="img/12.jpeg" />
<img width="250" alt="image" src="img/13.jpeg" />
<img width="250" alt="image" src="img/14.jpeg" />
<img width="250" alt="image" src="img/15.jpeg" />
<img width="250" alt="image" src="img/16.jpeg" />
<img width="250" alt="image" src="img/17.jpeg" />
<img width="250" alt="image" src="img/18.jpeg" />
<img width="250" alt="image" src="img/A0301.png" />
<img width="250" alt="image" src="img/A0302.png" />
<img width="250" alt="image" src="img/A0303.png" />
<img width="250" alt="image" src="img/A0304.png" />
<img width="250" alt="image" src="img/A0601.png" />
<img width="250" alt="image" src="img/A0602.png" />
<img width="250" alt="image" src="img/A0603.png" />
<img width="250" alt="image" src="img/A0604.png" />

## Características

### Gestión de Permisos
- **Cámara**: Captura de fotos con manejo seguro
- **Galería**: Acceso a imágenes del dispositivo
- **Micrófono**: Grabación de audio con permisos dinámicos
- **Contactos**: Lectura segura de la lista de contactos
- **Teléfono**: Funcionalidad de llamadas
- **Ubicación**: Acceso a localización del usuario

### Seguridad y Privacidad
- **Protección de Datos**: Sistema de logging encriptado
- **Almacenamiento Seguro**: Base de datos SQLCipher
- **Permisos Runtime**: Solicitud dinámica de permisos
- **Política de Privacidad**: Información transparente sobre el uso de datos

## Tecnologías Utilizadas

- **Kotlin**: Lenguaje principal
- **Android Jetpack**: Componentes modernos
- **SQLCipher**: Encriptación de base de datos
- **Camera2 API**: Manejo avanzado de cámara
- **Security Crypto**: Encriptación de datos sensibles

## Instalación

1. Clona el repositorio
2. Abre el proyecto en Android Studio
3. Sincroniza las dependencias
4. Ejecuta en dispositivo o emulador

## Estructura del Proyecto

```
📁 app/
├── 📁 src/main/java/com/example/seguridad_priv_a/
│   ├── 📁 adapter/
│   │   └── 📄 PermissionsAdapter.kt       # Adaptador RecyclerView
│   ├── 📁 data/
│   │   ├── 📄 DataProtectionManager.kt    # Gestión de datos seguros
│   │   └── 📄 PermissionItem.kt           # Modelo de permisos
│   ├── 📁 forense/
│   │   └── 📄 ForensicAnalysisSystem.kt   # Análisis Forense y Compliance
│   ├── 📁 security/
│   │   ├── 📄 AdvancedAnonymizer.kt       # Anonimización avanzada de datos
│   │   ├── 📄 AntiTampering.kt            # Detección de manipulación de la app
│   │   ├── 📄 AppSignatureVerifier.kt     # Verificación de firma de la app
│   │   ├── 📄 CertificatePinnerHelper.kt  # Pinning de certificados SSL
│   │   ├── 📄 SecurityAuditManager.kt     # Gestión de auditorías de seguridad
│   │   ├── 📄 StringObfuscator.kt         # Ofuscación de cadenas
│   │   └── 📄 ZeroTrustManager.kt         # Implementación de Zero Trust
│   ├── 📄 MainActivity.kt                 # Pantalla principal
│   ├── 📄 PermissionsApplication.kt       # Configuración global
│   └── 📄 [Actividades individuales]
└── 📁 res/
    ├── 📁 layout/                         # Diseños XML
    ├── 📁 values/                         # Recursos y strings
    └── 📁 xml/                            # Configuraciones
```

## Permisos Requeridos

- `CAMERA` - Para captura de fotos
- `READ_MEDIA_IMAGES` - Acceso a galería
- `RECORD_AUDIO` - Grabación de audio
- `READ_CONTACTS` - Lectura de contactos
- `CALL_PHONE` - Realizar llamadas
- `ACCESS_COARSE_LOCATION` - Ubicación aproximada

## Licencia

Este proyecto es para fines educativos y demostrativos.
