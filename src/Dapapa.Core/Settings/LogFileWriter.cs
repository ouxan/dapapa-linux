using System.IO;
using System.Text;
using System.Threading.Channels;

namespace Dapapa.Core
{
    internal sealed class LogFileWriter : IAsyncDisposable
    {
        private readonly Channel<string> _lines = Channel.CreateBounded<string>(new BoundedChannelOptions(2048)
            { SingleReader = true, FullMode = BoundedChannelFullMode.Wait });
        private readonly Task _worker;
        private readonly string _path;
        private readonly long _maxBytes;
        internal long DroppedLines;

        public LogFileWriter(string path, long maxBytes = 2 * 1024 * 1024)
        {
            _path = path;
            _maxBytes = maxBytes;
            _worker = Task.Run(WriteAsync);
        }

        public string Write(string line)
        {
            string entry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {line}";
            if (!_lines.Writer.TryWrite(entry)) Interlocked.Increment(ref DroppedLines);
            return entry;
        }

        private async Task WriteAsync()
        {
            var batch = new StringBuilder();
            await foreach (string first in _lines.Reader.ReadAllAsync().ConfigureAwait(false))
            {
                batch.Clear().AppendLine(first);
                for (int i = 0; i < 127 && _lines.Reader.TryRead(out var next); i++) batch.AppendLine(next);
                try
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
                    long size = File.Exists(_path) ? new FileInfo(_path).Length : 0;
                    if (size + Encoding.UTF8.GetByteCount(batch.ToString()) > _maxBytes)
                    {
                        for (int i = 3; i > 1; i--)
                            if (File.Exists(_path + "." + (i - 1))) File.Move(_path + "." + (i - 1), _path + "." + i, true);
                        if (File.Exists(_path)) File.Move(_path, _path + ".1", true);
                    }
                    await File.AppendAllTextAsync(_path, batch.ToString()).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                { Interlocked.Increment(ref DroppedLines); }
            }
        }

        public async ValueTask DisposeAsync()
        {
            _lines.Writer.TryComplete();
            await _worker.ConfigureAwait(false);
        }
    }
}
