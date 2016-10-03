class Identity < ApplicationRecord
  belongs_to :user

  validates :uid, :provider, presence: true
  validates :uid, uniqueness: true

  def self.find_for_oauth(auth)
    find_or_create_by(uid: auth.uid, provider: auth.provider)
  end
end
