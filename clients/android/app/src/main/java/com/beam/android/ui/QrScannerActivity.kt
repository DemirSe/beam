package com.beam.android.ui

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.os.SystemClock
import android.util.Size
import android.widget.Toast
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updatePadding
import com.beam.android.R
import com.beam.android.databinding.ActivityQrScannerBinding
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/** CameraX preview plus a ZXing multi-format reader limited to QR codes. */
class QrScannerActivity : AppCompatActivity() {

    private lateinit var binding: ActivityQrScannerBinding

    private val cameraExecutor = Executors.newSingleThreadExecutor()
    private val handled = AtomicBoolean(false)
    private var lastInvalidQrAtMs = 0L

    // Reused on the single-threaded cameraExecutor to avoid per-frame GC churn.
    private var frameBuffer = ByteArray(0)
    private var rotatedBuffer = ByteArray(0)
    private var lastAnalyzeAtMs = 0L
    private var analyzedFrames = 0

    private val fastReader = MultiFormatReader().apply {
        setHints(mapOf(DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE)))
    }

    private val hardReader = MultiFormatReader().apply {
        setHints(
            mapOf(
                DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
                DecodeHintType.TRY_HARDER to true,
            ),
        )
    }

    private val cameraPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (granted) {
            startCamera()
        } else {
            Toast.makeText(this, R.string.qr_permission_required, Toast.LENGTH_LONG).show()
            finish()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        binding = ActivityQrScannerBinding.inflate(layoutInflater)
        setContentView(binding.root)
        val initialTop = binding.qrTopBar.paddingTop
        val initialLeft = binding.qrTopBar.paddingLeft
        val initialRight = binding.qrTopBar.paddingRight
        ViewCompat.setOnApplyWindowInsetsListener(binding.qrTopBar) { v, insets ->
            val bars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout(),
            )
            v.updatePadding(
                left = initialLeft + bars.left,
                top = initialTop + bars.top,
                right = initialRight + bars.right,
            )
            insets
        }
        binding.closeButton.setOnClickListener { finish() }

        val granted = ContextCompat.checkSelfPermission(
            this,
            Manifest.permission.CAMERA,
        ) == PackageManager.PERMISSION_GRANTED
        if (granted) startCamera() else cameraPermissionLauncher.launch(Manifest.permission.CAMERA)
    }

    override fun onDestroy() {
        cameraExecutor.shutdownNow()
        super.onDestroy()
    }

    private fun startCamera() {
        val future = ProcessCameraProvider.getInstance(this)
        future.addListener({
            if (isFinishing || isDestroyed) return@addListener
            val provider = runCatching { future.get() }.getOrNull() ?: return@addListener
            val preview = Preview.Builder().build()
            preview.setSurfaceProvider(binding.previewView.surfaceProvider)
            val resolutionSelector = ResolutionSelector.Builder()
                .setResolutionStrategy(
                    ResolutionStrategy(
                        Size(TARGET_ANALYSIS_WIDTH, TARGET_ANALYSIS_HEIGHT),
                        ResolutionStrategy.FALLBACK_RULE_CLOSEST_HIGHER_THEN_LOWER,
                    ),
                )
                .build()
            val analysis = ImageAnalysis.Builder()
                .setResolutionSelector(resolutionSelector)
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()
            analysis.setAnalyzer(cameraExecutor) { proxy -> analyze(proxy) }
            val bound = runCatching {
                provider.unbindAll()
                provider.bindToLifecycle(
                    this,
                    CameraSelector.DEFAULT_BACK_CAMERA,
                    preview,
                    analysis,
                )
            }
            if (bound.isFailure) {
                Toast.makeText(this, R.string.qr_error, Toast.LENGTH_LONG).show()
                finish()
            }
        }, ContextCompat.getMainExecutor(this))
    }

    private fun analyze(proxy: ImageProxy) {
        try {
            if (!handled.get()) decodeFrame(proxy)
        } catch (_: Exception) {
            // A bad frame is not fatal; keep scanning.
        } finally {
            proxy.close()
        }
    }

    private fun decodeFrame(proxy: ImageProxy) {
        val now = SystemClock.elapsedRealtime()
        if (now - lastAnalyzeAtMs < MIN_ANALYZE_INTERVAL_MS) return
        lastAnalyzeAtMs = now
        analyzedFrames += 1

        val plane = proxy.planes.firstOrNull() ?: return
        val buffer = plane.buffer
        val remaining = buffer.remaining()
        if (frameBuffer.size < remaining) frameBuffer = ByteArray(remaining)
        buffer.get(frameBuffer, 0, remaining)

        val width = proxy.width
        val height = proxy.height
        val rowStride = plane.rowStride
        if (rowStride < width) return
        val source = luminanceSource(
            frameBuffer,
            remaining,
            rowStride,
            width,
            height,
            plane.pixelStride,
            proxy.imageInfo.rotationDegrees,
        ) ?: return
        val bitmap = BinaryBitmap(HybridBinarizer(source))
        val text = decodeWith(fastReader, bitmap)
            ?: if (analyzedFrames % TRY_HARDER_EVERY_N_FRAMES == 0) {
                decodeWith(hardReader, bitmap)
            } else {
                null
            }
        if (text.isNullOrBlank()) return

        if (!text.startsWith("vless://", ignoreCase = true)) {
            notifyInvalidQr()
            return
        }
        if (!handled.compareAndSet(false, true)) return
        runOnUiThread {
            setResult(RESULT_OK, Intent().putExtra(EXTRA_RESULT, text.take(MAX_RESULT_LENGTH)))
            finish()
        }
    }

    private fun decodeWith(reader: MultiFormatReader, bitmap: BinaryBitmap): String? = try {
        reader.decodeWithState(bitmap)?.text
    } catch (_: Exception) {
        null
    } finally {
        reader.reset()
    }

    private fun notifyInvalidQr() {
        val now = SystemClock.elapsedRealtime()
        if (now - lastInvalidQrAtMs < INVALID_QR_TOAST_INTERVAL_MS) return
        lastInvalidQrAtMs = now
        runOnUiThread { Toast.makeText(this, R.string.qr_invalid, Toast.LENGTH_SHORT).show() }
    }

    /**
     * Builds an upright Y-plane source. CameraX stays in sensor orientation, so
     * a QR code is unreadable until the plane is rotated by [rotationDegrees].
     */
    private fun luminanceSource(
        data: ByteArray,
        dataLen: Int,
        rowStride: Int,
        width: Int,
        height: Int,
        pixelStride: Int,
        rotationDegrees: Int,
    ): PlanarYUVLuminanceSource? {
        val rotation = ((rotationDegrees % 360) + 360) % 360
        if (rotation == 0 && pixelStride == 1 && dataLen >= rowStride * height) {
            return PlanarYUVLuminanceSource(data, rowStride, height, 0, 0, width, height, false)
        }
        val swap = rotation == 90 || rotation == 270
        val outWidth = if (swap) height else width
        val outHeight = if (swap) width else height
        val needed = outWidth * outHeight
        if (rotatedBuffer.size < needed) rotatedBuffer = ByteArray(needed)
        val out = rotatedBuffer
        if (height > 0 && (height - 1) * rowStride + (width - 1) * pixelStride >= dataLen) {
            return null
        }
        when (rotation) {
            90 -> {
                for (y in 0 until height) {
                    val row = y * rowStride
                    val dstCol = height - 1 - y
                    for (x in 0 until width) {
                        out[x * outWidth + dstCol] = data[row + x * pixelStride]
                    }
                }
            }
            180 -> {
                for (y in 0 until height) {
                    val row = y * rowStride
                    val dstRow = (height - 1 - y) * width
                    for (x in 0 until width) {
                        out[dstRow + (width - 1 - x)] = data[row + x * pixelStride]
                    }
                }
            }
            270 -> {
                for (y in 0 until height) {
                    val row = y * rowStride
                    for (x in 0 until width) {
                        out[(width - 1 - x) * outWidth + y] = data[row + x * pixelStride]
                    }
                }
            }
            else -> {
                for (y in 0 until height) {
                    val row = y * rowStride
                    val dstRow = y * width
                    for (x in 0 until width) {
                        out[dstRow + x] = data[row + x * pixelStride]
                    }
                }
            }
        }
        return PlanarYUVLuminanceSource(out, outWidth, outHeight, 0, 0, outWidth, outHeight, false)
    }

    companion object {
        const val EXTRA_RESULT = "com.beam.android.extra.QR_RESULT"

        // Matches beam-core MAX_CLIENT_LINK_LEN and the ProfilesFragment clip:
        // a longer link is rejected by the engine anyway.
        private const val MAX_RESULT_LENGTH = 2048
        private const val INVALID_QR_TOAST_INTERVAL_MS = 2_000L
        private const val TARGET_ANALYSIS_WIDTH = 1280
        private const val TARGET_ANALYSIS_HEIGHT = 720
        private const val MIN_ANALYZE_INTERVAL_MS = 100L
        private const val TRY_HARDER_EVERY_N_FRAMES = 3
    }
}
