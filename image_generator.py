import os
import logging
from PIL import Image

logger = logging.getLogger(__name__)

class ImageGenerator:
    def __init__(self, config):
        self.config = config

    def bytes_to_png(self, standardized_bytes: bytes, output_path: str) -> bool:
        """Converts a 784-byte stream cleanly into an MNIST-like 28x28 grayscale image."""
        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            # Instantiate an L-mode (8-bit grayscale) Image canvas directly from raw memory
            # img = Image.frombytes('L', self.config.image_dimensions, standardized_bytes)
            expected_size = (
                self.config.image_dimensions[0]
                * self.config.image_dimensions[1]
            )

            if len(standardized_bytes) != expected_size:
                logger.error(
                    f"Expected {expected_size} bytes but got {len(standardized_bytes)}"
                )
                return False
            img = Image.frombytes(
                'L',
                self.config.image_dimensions,
                standardized_bytes
            )

            img.save(output_path, "PNG")
            scaled_img = img.resize (
            (
                self.config.image_dimensions[0] * self.config.scale_factor,
                self.config.image_dimensions[1] * self.config.scale_factor
            ),
                Image.Resampling.NEAREST
            )
            base, ext = os.path.splitext(output_path)
            scaled_output = f"{base}_scaled{ext}"
            scaled_img.save(scaled_output, "PNG")

            return True
        except Exception as e:
            logger.error(f"Failed to save image structure to {output_path}: {e}")
            return False