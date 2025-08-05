# Evaluación Técnica: Análisis y Mejora de Seguridad en Aplicación Android

**Alumno:** [Jose Manuel Vasquez Ramos](https://github.com/josevasquezramos)
**Código:** [0202114010](mailto:202114010@uns.edu.pe)

**Docente:** [Johan Max Alexander López Heredia](https://github.com/GxJohan)
**Asignatura:** Aplicaciones Móviles

## Introducción
Esta evaluación técnica se basa en una aplicación Android que implementa un sistema de demostración de permisos y protección de datos. La aplicación utiliza tecnologías modernas como Kotlin, Android Security Crypto, SQLCipher y patrones de arquitectura MVVM.

## Parte 1: Análisis de Seguridad Básico (0-7 puntos)

### 1.1 Identificación de Vulnerabilidades (2 puntos)

Analiza el archivo [`DataProtectionManager.kt`](https://github.com/josevasquezramos/seguridad_priv_a/blob/master/app/src/main/java/com/example/seguridad_priv_a/data/DataProtectionManager.kt) y responde:

#### ¿Qué método de encriptación se utiliza para proteger datos sensibles?

El método de encriptación utilizado para proteger datos sensibles es AES-256-GCM (Advanced Encryption Standard con un tamaño de clave de 256 bits en modo Galois/Counter Mode). Esto se implementa mediante la clase `EncryptedSharedPreferences` de la librería Android Security Crypto, que utiliza:
- **PrefKeyEncryptionScheme.AES256_SIV** para encriptar las claves.
- **PrefValueEncryptionScheme.AES256_GCM** para encriptar los valores.

#### Identifica al menos 2 posibles vulnerabilidades en la implementación actual del logging

- **Vulnerabilidad 1: Almacenamiento de logs en SharedPreferences sin encriptar.**
    Los logs de acceso se guardan en `SharedPreferences` sin encriptar (`accessLogPrefs`), lo que podría exponer información sensible (como timestamps, acciones realizadas, etc.) si el dispositivo es comprometido.
    - **Riesgo:** Un atacante con acceso físico al dispositivo podría leer los logs para entender patrones de uso o identificar datos sensibles.

- **Vulnerabilidad 2: Falta de sanitización en los logs.**
    Los logs registran directamente mensajes como `"Error al procesar imagen: ${e.message}"` o `"Llamada simulada a número anonimizado: $anonymizedNumber"`. Si `e.message` o `anonymizedNumber` contienen caracteres maliciosos o secuencias de escape, podrían explotarse para ataques de inyección (por ejemplo si los logs se visualizan en un sistema vulnerable).
    - **Solución:** Aplicar sanitización (ej. eliminar saltos de línea o caracteres especiales) antes de guardar los logs.

#### ¿Qué sucede si falla la inicialización del sistema de encriptación?

- **Fallback a SharedPreferences no encriptados:**
    En el bloque `catch (e: Exception)`, se inicializa `encryptedPrefs` como un `SharedPreferences` normal (`Context.MODE_PRIVATE`). Esto significa que los datos sensibles se guardarán sin encriptación, lo que reduce la seguridad.

- **Riesgo:**
    Si la encriptación falla (ej. por problemas con `MasterKey`), los datos quedarán almacenados en claro, vulnerables a extracción en dispositivos rooted o mediante ataques de acceso físico.

- **Mejora posible:**
    - Notificar al usuario y deshabilitar funcionalidades sensibles.
    - Usar un mecanismo de fallback alternativo (por ejemplo SQLCipher) en lugar de SharedPreferences no encriptados.

### 1.2 Permisos y Manifiesto (2 puntos)

Examina [`AndroidManifest.xml`](https://github.com/josevasquezramos/seguridad_priv_a/blob/master/app/src/main/AndroidManifest.xml) y [`MainActivity.kt`](https://github.com/josevasquezramos/seguridad_priv_a/blob/master/app/src/main/java/com/example/seguridad_priv_a/MainActivity.kt):

#### Lista todos los permisos peligrosos declarados en el manifiesto

Los permisos peligrosos (*dangerous permissions*) declarados en [`AndroidManifest.xml`](https://github.com/josevasquezramos/seguridad_priv_a/blob/master/app/src/main/AndroidManifest.xml) son:

1. `android.permission.CAMERA`
2. `android.permission.READ_EXTERNAL_STORAGE` (obsoleto en Android 11+, reemplazado por `READ_MEDIA_IMAGES`)
3. `android.permission.READ_MEDIA_IMAGES` (requerido en Android 13+)
4. `android.permission.RECORD_AUDIO`
5. `android.permission.READ_CONTACTS`
6. `android.permission.CALL_PHONE`
7. `android.permission.SEND_SMS`
8. `android.permission.ACCESS_COARSE_LOCATION`

Nota:

- `ACCESS_NETWORK_STATE` no es un permiso peligroso (es de tipo normal).
- `READ_EXTERNAL_STORAGE` está obsoleto en versiones recientes de Android, pero aún puede aparecer para compatibilidad.

#### ¿Qué patrón se utiliza para solicitar permisos en runtime?

El patrón utilizado es el **sistema de permisos en tiempo de ejecución (runtime permissions)** introducido en Android 6.0 (API 23), implementado mediante:

- **`ActivityResultContracts.RequestPermission()`**:
    - Se registra un `launcher` (`requestPermissionLauncher`) para manejar la respuesta del usuario.
    - En [`MainActivity.kt`](https://github.com/josevasquezramos/seguridad_priv_a/blob/master/app/src/main/java/com/example/seguridad_priv_a/MainActivity.kt), se usa:

    ```kotlin
    private val requestPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        // Lógica para actualizar el estado del permiso
    }
    ```

- **Flujo de solicitud:**
    - Se verifica el permiso con `ContextCompat.checkSelfPermission()`.
    - Si no está concedido, se solicita con `requestPermissionLauncher.launch(perm)`.
    - Si el usuario deniega el permiso, se puede mostrar una explicación con `shouldShowRequestPermissionRationale()`.

    ```kotlin
    private fun handlePermissionClick(permission: PermissionItem) {
        when {
            permission.status == PermissionStatus.NOT_REQUESTED -> requestPermission(permission)
            permission.status == PermissionStatus.DENIED -> openActivity(permission) // Manejar denegación
        }
    }
    ```

#### Identifica qué configuración de seguridad previene backups automáticos

La prevención de backups automáticos se configura en el [`AndroidManifest.xml`](https://github.com/josevasquezramos/seguridad_priv_a/blob/master/app/src/main/AndroidManifest.xml) con:

1. `android:allowBackup="false"`:
    - Desactiva el backup automático de la app en Google Drive.
    - Evita que datos sensibles se incluyan en backups no controlados.

2. `android:fullBackupContent="@xml/backup_rules"`:
    Si `allowBackup="true"`, este atributo permite definir reglas personalizadas para excluir datos sensibles (pero en este caso está desactivado).

**Justificación:**

- Sin `allowBackup="false"`, un atacante con acceso físico al dispositivo podría restaurar datos de la app desde un backup.
- La combinación con `dataExtractionRules` (en Android 12+) refuerza la protección contra extracción de datos por apps de backup no autorizadas.

### 1.3 Gestión de Archivos (3 puntos)

Revisa [`CameraActivity.kt`](https://github.com/josevasquezramos/seguridad_priv_a/blob/master/app/src/main/java/com/example/seguridad_priv_a/CameraActivity.kt) y [`file_paths.xml`](https://github.com/josevasquezramos/seguridad_priv_a/blob/master/app/src/main/res/xml/file_paths.xml):

#### ¿Cómo se implementa la compartición segura de archivos de imágenes?

La compartición segura se implementa mediante `FileProvider`, un componente de Android que permite compartir archivos entre apps de forma controlada y sin exponer rutas directas (`file://`). Los pasos clave son:

1. Definición del `FileProvider` en [`AndroidManifest.xml`](https://github.com/josevasquezramos/seguridad_priv_a/blob/master/app/src/main/AndroidManifest.xml):

    ```xml
    <provider
        android:name="androidx.core.content.FileProvider"
        android:authorities="com.example.seguridad_priv_a.fileprovider"
        android:exported="false"
        android:grantUriPermissions="true">
        <meta-data
            android:name="android.support.FILE_PROVIDER_PATHS"
            android:resource="@xml/file_paths" />
    </provider>
    ```

    - `exported="false"`: Evita que otras apps accedan directamente al provider.
    - `grantUriPermissions="true"`: Permite otorgar permisos temporales a URIs específicos.

2. Configuración de rutas permitidas en [`file_paths.xml`](https://github.com/josevasquezramos/seguridad_priv_a/blob/master/app/src/main/res/xml/file_paths.xml):

    ```xml
    <paths>
        <external-files-path name="my_images" path="Pictures" />
    </paths>
    ```

    - Limita el acceso solo al directorio `Pictures` dentro del almacenamiento externo privado de la app (`Context.getExternalFilesDir()`).

3. Generación de URI segura en [`CameraActivity.kt`](https://github.com/josevasquezramos/seguridad_priv_a/blob/master/app/src/main/java/com/example/seguridad_priv_a/CameraActivity.kt):

    ```kotlin
    currentPhotoUri = FileProvider.getUriForFile(
        this,
        "com.example.seguridad_priv_a.fileprovider",
        photoFile
    )
    ```

    - Convierte la ruta del archivo (`photoFile`) en una URI segura (`content://`).

4. Uso de la URI con `ActivityResultContracts.TakePicture()`:

    ```kotlin
    takePictureLauncher.launch(currentPhotoUri)
    ```

    - La cámara recibe la URI con permisos temporales para escribir en el archivo.

#### ¿Qué autoridad se utiliza para el FileProvider?

La autoridad (*authority*) definida es:

```xml
android:authorities="com.example.seguridad_priv_a.fileprovider"
```

Esta cadena **debe ser única** en el dispositivo y generalmente sigue el formato:

```xml
<package-name>.fileprovider
```

- **Uso en código:** Se referencia la misma autoridad al llamar a `FileProvider.getUriForFile()`.

#### Explica por qué no se debe usar `file://` URIs directamente

Usar URIs con esquema `file://` presenta riesgos de seguridad:

1. Exposición de rutas del sistema de archivos

    Cualquier app con permisos de almacenamiento podría:

    - Acceder a los archivos.
    - Modificar o eliminar los archivos.
    - Ver rutas sensibles del sistema de archivos.

2. Violación de la política de seguridad de Android (`StrictMode`)

    Desde **Android 7.0 (API 24)**:

    - Las URIs `file://` están bloqueadas para compartir entre apps.
    - Usarlas lanza una excepción: `FileUriExposedException`.

3. Falta de control de permisos

    - Con `FileProvider`, se otorgan **permisos temporales** solo a apps específicas (por ejemplo, la cámara).
    - Con `file://`, **no hay restricciones**: cualquier app con permisos generales podría acceder.

4. Incompatibilidad con scoped storage

    - A partir de **Android 10+ (API 29)**, el acceso directo a rutas externas está restringido.
    - `FileProvider` se adapta automáticamente a estas restricciones.

**Ejemplo de vulnerabilidad:**
Si una app guarda una foto en `file:///storage/emulated/0/Android/data/com.example.app/Pictures/photo.jpg` y comparte la ruta, otra app maliciosa podría leerla sin permiso.
