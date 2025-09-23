/*
 * LibrePods - AirPods liberated from Apple’s ecosystem
 *
 * Copyright (C) 2025 LibrePods contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

@file:OptIn(ExperimentalEncodingApi::class)

package me.kavishdevar.librepods.composables

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import me.kavishdevar.librepods.R
import me.kavishdevar.librepods.services.ServiceManager
import me.kavishdevar.librepods.utils.AACPManager
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.math.roundToInt

@Composable
fun AdaptiveStrengthSlider() {
    val sliderValue = remember { mutableFloatStateOf(0f) }
    val service = ServiceManager.getService()!!
    LaunchedEffect(sliderValue) {
        val sliderValueFromAACP = service.aacpManager.controlCommandStatusList.find {
            it.identifier == AACPManager.Companion.ControlCommandIdentifiers.AUTO_ANC_STRENGTH
        }?.value?.takeIf { it.isNotEmpty() }?.get(0)
        sliderValueFromAACP?.toFloat()?.let { sliderValue.floatValue = (100 - it) }
    }

    val listener = remember {
        object : AACPManager.ControlCommandListener {
            override fun onControlCommandReceived(controlCommand: AACPManager.ControlCommand) {
                if (controlCommand.identifier == AACPManager.Companion.ControlCommandIdentifiers.AUTO_ANC_STRENGTH.value) {
                    controlCommand.value.takeIf { it.isNotEmpty() }?.get(0)?.toFloat()?.let {
                        sliderValue.floatValue = (100 - it)
                    }
                }
            }
        }
    }

    DisposableEffect(Unit) {
        service.aacpManager.registerControlCommandListener(
            AACPManager.Companion.ControlCommandIdentifiers.AUTO_ANC_STRENGTH,
            listener
        )
        onDispose {
            service.aacpManager.unregisterControlCommandListener(
                AACPManager.Companion.ControlCommandIdentifiers.AUTO_ANC_STRENGTH,
                listener
            )
        }
    }

    val isDarkTheme = isSystemInDarkTheme()

    val trackColor = if (isDarkTheme) Color(0xFFB3B3B3) else Color(0xFFD9D9D9)
    val thumbColor = if (isDarkTheme) Color(0xFFFFFFFF) else Color(0xFFFFFFFF)
    val labelTextColor = if (isDarkTheme) Color.White else Color.Black

    Column(
        modifier = Modifier
            .fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        StyledSlider(
            mutableFloatState = sliderValue,
            onValueChange = {
                sliderValue.floatValue = snapIfClose(it, listOf(0f, 50f, 100f))
            },
            valueRange = 0f..100f,
            snapPoints = listOf(0f, 50f, 100f),
            startLabel = stringResource(R.string.less_noise),
            endLabel = stringResource(R.string.more_noise),
            independent = false
        )
    }
}

@Preview
@Composable
fun AdaptiveStrengthSliderPreview() {
    AdaptiveStrengthSlider()
}

private fun snapIfClose(value: Float, points: List<Float>, threshold: Float = 0.05f): Float {
    val nearest = points.minByOrNull { kotlin.math.abs(it - value) } ?: value
    return if (kotlin.math.abs(nearest - value) <= threshold) nearest else value
}