-- Copyright (c) 2019
-- Mainflux
--
-- SPDX-License-Identifier: Apache-2.0


module Helpers exposing (appendIf, buildQueryParamList, checkEntity, faIcons, fontAwesome, genPagination, isChecked, offsetToPage, pageToOffset, parseString, response, validateInt, validateOffset)

import Bootstrap.Button as Button
import Bootstrap.Grid as Grid
import Bootstrap.Grid.Col as Col
import Bootstrap.Grid.Row as Row
import Bootstrap.Utilities.Spacing as Spacing
import Html exposing (Html, a, div, hr, li, nav, node, p, strong, text, ul)
import Html.Attributes exposing (..)
import Html.Events exposing (onClick)
import Http
import List.Extra
import Url.Builder as B



-- HTTP


response : String -> Html.Html msg
response resp =
    if String.length resp > 0 then
        Grid.row []
            [ Grid.col []
                [ hr [] []
                , p [] [ text ("response: " ++ resp) ]
                ]
            ]

    else
        Grid.row []
            [ Grid.col [] []
            ]



-- STRING


parseString : Maybe String -> String
parseString str =
    case str of
        Just s ->
            s

        Nothing ->
            ""



-- PAGINATION


buildQueryParamList : Int -> Int -> List B.QueryParameter
buildQueryParamList offset limit =
    [ B.int "offset" offset, B.int "limit" limit ]


validateInt : String -> Int -> Int
validateInt string default =
    case String.toInt string of
        Just num ->
            num

        Nothing ->
            default


pageToOffset : Int -> Int -> Int
pageToOffset page limit =
    (page - 1) * limit


offsetToPage : Int -> Int -> Int
offsetToPage offset limit =
    (offset // limit) + 1


validateOffset : Int -> Int -> Int -> Int
validateOffset offset total limit =
    if offset >= (total - 1) then
        Basics.max ((total - 1) - limit) 0

    else
        offset


genPagination : Int -> Int -> (Int -> msg) -> Html msg
genPagination total currPage msg =
    let
        pages =
            List.range 1 (Basics.ceiling (Basics.toFloat total / 10))

        cols =
            nav []
                [ ul [ class "pagination" ]
                    ([ li [ classList [ ( "page-item", True ), ( "disabled", currPage == 1 ) ] ]
                        [ a
                            ([ class "page-link" ]
                                |> appendIf (currPage > 1)
                                    (onClick (msg (currPage - 1)))
                            )
                            [ text "Previous" ]
                        ]
                     ]
                        ++ List.map
                            (\page ->
                                li [ classList [ ( "page-item", True ), ( "active", currPage == page ) ] ] [ a [ class "page-link", onClick (msg page) ] [ text (String.fromInt page) ] ]
                            )
                            pages
                        ++ [ li [ classList [ ( "page-item", True ), ( "disabled", disableNext currPage total ) ] ]
                                [ a
                                    ([ class "page-link" ]
                                        |> appendIf
                                            (not (disableNext currPage total))
                                            (onClick (msg (currPage + 1)))
                                    )
                                    [ text "Next" ]
                                ]
                           ]
                    )
                ]
    in
    Grid.row [] [ Grid.col [] [ cols ] ]



-- FONT-AWESOME


fontAwesome : Html msg
fontAwesome =
    node "link"
        [ rel "stylesheet"
        , href "https://use.fontawesome.com/releases/v5.7.2/css/all.css"
        , attribute "integrity" "sha384-fnmOCqbTlWIlj8LyTjo7mOUStjsKC4pOpQbqyi7RrhN7udi9RwhKkMHpvLbHG9Sr"
        , attribute "crossorigin" "anonymous"
        ]
        []


faIcons =
    { provision = class "fa fa-plus"
    , edit = class "fa fa-pen"
    , remove = class "fa fa-trash-alt"
    }



-- TABLE


checkEntity : String -> List String -> List String
checkEntity id checkedEntitiesIds =
    if List.member id checkedEntitiesIds then
        List.Extra.remove id checkedEntitiesIds

    else
        id :: checkedEntitiesIds


isChecked : String -> List String -> Bool
isChecked id checkedEntitiesIds =
    if List.member id checkedEntitiesIds then
        True

    else
        False


appendIf : Bool -> a -> List a -> List a
appendIf flag value list =
    if flag == True then
        list ++ [ value ]

    else
        list


disableNext : Int -> Int -> Bool
disableNext currPage total =
    currPage == Basics.ceiling (Basics.toFloat total / 10)
