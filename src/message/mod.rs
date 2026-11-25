mod attachment;
mod from_prior;
mod message;
mod pack_encrypted;
mod pack_plaintext;
mod pack_signed;
mod unpack;

pub use attachment::{
    Attachment, AttachmentBuilder, AttachmentData, Base64AttachmentData, JsonAttachmentData,
    LinksAttachmentData,
};

pub use from_prior::FromPrior;

pub use message::{Message, MessageBuilder};
pub use pack_encrypted::{MessagingServiceMetadata, PackEncryptedMetadata, PackEncryptedOptions};
pub use pack_signed::PackSignedMetadata;
pub use unpack::{SenderRequirement, UnpackMetadata, UnpackOptions};

pub(crate) use pack_encrypted::anoncrypt;

#[cfg(test)]
pub(crate) use pack_encrypted::authcrypt_raw;
