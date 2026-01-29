from aiortc import VideoStreamTrack
from av import VideoFrame
import asyncio
import threading
import time
import numpy as np

from picamera2 import Picamera2
import cv2


class MotionCameraStream(VideoStreamTrack):
    def __init__(self, target_size=(1280, 720), sensitivity=40):
        super().__init__()

        self.picam = Picamera2()

        config = self.picam.create_video_configuration(
            main={"size": target_size, "format": "RGB888"},
            controls={"AwbEnable": True, "AeEnable": True}
        )

        self.picam.configure(config)
        self.picam.start()

        self.frame = np.zeros((target_size[1], target_size[0], 3), dtype=np.uint8)

        self.prev_gray = None
        self.motion_detected = False
        self.sensitivity = sensitivity
        self.running = True

        time.sleep(1.5)  # AWB stabilisieren

        # eigener Frame-Reader
        self.thread = threading.Thread(target=self._reader, daemon=True)
        self.thread.start()

    def _reader(self):
        while self.running:
            frame = self.picam.capture_array()     # RGB888 Frame

            # Bewegung erkennen
            gray = cv2.cvtColor(frame, cv2.COLOR_RGB2GRAY)
            gray = cv2.GaussianBlur(gray, (21, 21), 0)

            if self.prev_gray is not None:
                diff = cv2.absdiff(self.prev_gray, gray)
                thresh = cv2.threshold(diff, 25, 255, cv2.THRESH_BINARY)[1]
                motion_level = np.sum(thresh) / 255
                self.motion_detected = motion_level > self.sensitivity * 1000

            self.prev_gray = gray
            self.frame = frame

    async def recv(self):
        pts, time_base = await self.next_timestamp()
        frm = VideoFrame.from_ndarray(self.frame, format="rgb24")
        frm.pts = pts
        frm.time_base = time_base
        return frm

    def stop(self):
        self.running = False
        self.picam.stop()
        print("Kamera gestoppt.")
