set shell := ['nu', '-c']
set dotenv-load := true

[private]
default:
    just -l

b:
    cargo build

t:
    cargo test

r:
    cargo build --release

# Download and deploy pkg-mrs binary from tar.gz artifact
deploy DOWNLOAD_URL SERVER PORT:
    #!/usr/bin/env nu
    let temp_dir = (mktemp -d)
    let archive_path = $"($temp_dir)/pkg-mrs.tar.gz"
    print $"Downloading artifact..."
    curl -L -o $archive_path {{ DOWNLOAD_URL }}
    print $"Extracting pkg-mrs binary..."
    tar -xzf $archive_path -C $temp_dir pkg-mrs
    print $"Deploying pkg-mrs to {{ SERVER }}..."
    scp -P {{ PORT }} $"($temp_dir)/pkg-mrs"  {{ SERVER }}:/data/software/pkg-mrs/pkg-mrs
    print "Cleaning up temporary files..."
    rm -rf $temp_dir
    print "Deployment complete!"
