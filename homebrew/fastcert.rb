class Fastcert < Formula
  desc "Simple zero-config tool for making locally-trusted development certificates"
  homepage "https://github.com/ozankasikci/fastcert"
  url "https://github.com/ozankasikci/fastcert/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "2d7563d5757d053d1fec5c24117ef7ffe22d10038a03deaa20bed9128b29bab0"
  license "MIT"
  head "https://github.com/ozankasikci/fastcert.git", branch: "master"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    # Test that the binary exists and runs
    system "#{bin}/fastcert", "-CAROOT"
  end
end
