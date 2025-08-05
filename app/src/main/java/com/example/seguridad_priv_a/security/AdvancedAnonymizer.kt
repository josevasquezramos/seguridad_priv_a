package com.example.seguridad_priv_a.security

import kotlin.math.abs
import kotlin.math.ln
import kotlin.random.Random

class AdvancedAnonymizer {

    // Políticas de enmascaramiento predefinidas
    enum class MaskingPolicy {
        FULL, PARTIAL, NUMERIC_ONLY, SENSITIVE_ONLY
    }

    data class PersonalData(val originalData: Map<String, Any>)
    data class AnonymizedData(val anonymizedData: Map<String, Any>)
    data class NumericData(val value: Double, val min: Double, val max: Double)

    /**
     * Implementa k-anonymity agrupando y generalizando datos
     */
    fun anonymizeWithKAnonymity(data: List<PersonalData>, k: Int): List<AnonymizedData> {
        if (data.size < k) {
            throw IllegalArgumentException("El conjunto de datos es más pequeño que k=$k")
        }

        // Agrupar datos por atributos cuasi-identificadores (simplificado)
        val groupedData = data.groupBy { record ->
            // Aquí deberías definir qué campos son cuasi-identificadores
            // Ejemplo simplificado: agrupar por primeros caracteres de campos string
            record.originalData.mapValues { (_, value) ->
                when (value) {
                    is String -> value.take(3) + "***" // Generalización
                    is Number -> (value.toDouble() / 10).toInt() * 10 // Redondeo
                    else -> "***"
                }
            }
        }

        // Aplicar k-anonimidad (eliminar grupos con menos de k elementos)
        val anonymizedGroups = groupedData.filter { it.value.size >= k }

        // Convertir a formato de salida
        return anonymizedGroups.flatMap { group ->
            group.value.map { record ->
                AnonymizedData(group.key)
            }
        }
    }

    /**
     * Aplica privacidad diferencial mediante el mecanismo de Laplace
     */
    fun applyDifferentialPrivacy(data: NumericData, epsilon: Double): NumericData {
        require(epsilon > 0) { "Épsilon debe ser mayor que 0" }

        val sensitivity = (data.max - data.min) / 10 // Sensibilidad aproximada
        val scale = sensitivity / epsilon
        val noise = laplaceMechanism(scale)

        val noisyValue = data.value + noise
        return data.copy(value = noisyValue.coerceIn(data.min, data.max))
    }

    private fun laplaceMechanism(scale: Double): Double {
        val u = Random.nextDouble(-0.5, 0.5)
        return -scale * ln(1 - 2 * abs(u)) * if (u < 0) -1 else 1
    }

    /**
     * Enmascara datos según el tipo y política especificada
     */
    fun maskByDataType(data: Any, maskingPolicy: MaskingPolicy): Any {
        return when (data) {
            is String -> when (maskingPolicy) {
                MaskingPolicy.FULL -> "***"
                MaskingPolicy.PARTIAL -> data.replace(Regex("[A-Za-z0-9]"), "*")
                MaskingPolicy.NUMERIC_ONLY -> data.replace(Regex("[0-9]"), "#")
                MaskingPolicy.SENSITIVE_ONLY -> if (isSensitive(data)) "***" else data
            }
            is Number -> when (maskingPolicy) {
                MaskingPolicy.FULL, MaskingPolicy.SENSITIVE_ONLY -> 0
                MaskingPolicy.PARTIAL -> (data.toDouble() / 100).toInt() * 100
                MaskingPolicy.NUMERIC_ONLY -> data
            }
            else -> "***"
        }
    }

    private fun isSensitive(data: String): Boolean {
        // Lógica para detectar datos sensibles (simplificado)
        return data.contains(Regex("name|address|email|phone|ssn", RegexOption.IGNORE_CASE))
    }

    /**
     * Método mejorado de anonimización que integra las técnicas avanzadas
     */
    fun anonymizeData(data: String): String {
        // Primero aplicamos enmascaramiento por tipo
        val masked = maskByDataType(data, MaskingPolicy.SENSITIVE_ONLY).toString()

        // Para datos numéricos podríamos aplicar privacidad diferencial
        if (data.matches(Regex(".*\\d+.*"))) {
            val numericData = NumericData(
                value = data.filter { it.isDigit() }.take(10).toDoubleOrNull() ?: 0.0,
                min = 0.0,
                max = 9999999999.0
            )
            val dpData = applyDifferentialPrivacy(numericData, 0.1)
            return masked.replace(Regex("\\d+"), dpData.value.toInt().toString())
        }

        return masked
    }
}