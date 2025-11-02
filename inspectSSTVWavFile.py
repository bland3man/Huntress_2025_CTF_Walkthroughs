# Load and visualize the uploaded audio as a spectrogram to illustrate SSTV-like structure.
import wave, numpy as np, matplotlib.pyplot as plt

path = "/mnt/data/maximum_sound.wav"

with wave.open(path, 'rb') as w:
    n_channels = w.getnchannels()
    sampwidth = w.getsampwidth()
    framerate = w.getframerate()
    n_frames = w.getnframes()
    audio = w.readframes(n_frames)

# Convert to numpy array (int16 assumed), mono mix if needed
dtype = {1: np.uint8, 2: np.int16, 3: np.int32, 4: np.int32}.get(sampwidth, np.int16)
sig = np.frombuffer(audio, dtype=dtype)

# If 8-bit unsigned, center it
if sampwidth == 1:
    sig = sig.astype(np.int16) - 128

# If stereo, downmix to mono
if n_channels > 1:
    sig = sig.reshape(-1, n_channels).mean(axis=1)

# Normalize to float
sig = sig.astype(np.float32)
maxabs = np.max(np.abs(sig)) if np.max(np.abs(sig)) != 0 else 1.0
sig = sig / maxabs

duration_sec = len(sig) / framerate

print(f"Channels: {n_channels}, Sample width: {sampwidth*8} bits, Rate: {framerate} Hz, Duration: {duration_sec:.2f} s")

# Plot spectrogram (nperseg/FFT size tuned to show ~1–3 kHz features clearly)
plt.figure(figsize=(10, 5))
Pxx, freqs, bins, im = plt.specgram(sig, NFFT=2048, Fs=framerate, noverlap=1024, scale='dB', mode='magnitude')
plt.title("Spectrogram of maximum_sound.wav")
plt.xlabel("Time (s)")
plt.ylabel("Frequency (Hz)")
plt.ylim(0, 4000)  # SSTV energy is typically in the 0.5–3 kHz region
plt.show()

# create the png
sox "maximum_sound.wav" -n rate 11025 spectrogram -x 2400 -y 1024 -z 120 -r -o sstv_spectrogram.png