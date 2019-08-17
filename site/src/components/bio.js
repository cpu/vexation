/**
 * Bio component that queries for data
 * with Gatsby's useStaticQuery component
 *
 * See: https://www.gatsbyjs.org/docs/use-static-query/
 */

import React from "react"
import { useStaticQuery, graphql } from "gatsby"

import { rhythm } from "../utils/typography"

const Bio = () => {
  const data = useStaticQuery(graphql`
    query BioQuery {
      site {
        siteMetadata {
          author
          social {
            twitter
          }
        }
      }
    }
  `)

  const { author, social } = data.site.siteMetadata
  return (
    <div
      style={{
        marginBottom: rhythm(1),
      }}
    >
      <p
        style={{
          marginBottom: 10,
        }}>
          VeXation is an on-going project by
          {` `}
          <a href={`https://twitter.com/${social.twitter}`}>
            {author}
          </a>
          {` `}
          exploring retro computer virus development.
      </p>
      <p>
          Follow along while I write a portable executable (PE) file infector virus targetting Windows 95 using Borland Turbo Assembler 5.0 and other period accurate 90s hacking/VX tools.
      </p>
    </div>
  )
}

export default Bio
