# frozen_string_literal: true

module WPScan
  module DB
    # Plugin DB
    class Plugin < WpItem
      # @return [ String ]
      def self.db_file
        @db_file ||= DB_DIR.join('plugins.json').to_s
      end
    end
  end
end
